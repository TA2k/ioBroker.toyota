'use strict';

/*
 * Created with @iobroker/create-adapter v2.0.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const Json2iob = require('json2iob');
const qs = require('qs');
const tough = require('tough-cookie');
const { HttpsCookieAgent } = require('http-cookie-agent/http');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

class Toyota extends utils.Adapter {
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  constructor(options) {
    super({
      ...options,
      name: 'toyota',
    });
    this.on('ready', this.onReady.bind(this));
    this.on('stateChange', this.onStateChange.bind(this));
    this.on('unload', this.onUnload.bind(this));
    this.deviceArray = [];
    this.json2iob = new Json2iob(this);
    this.token = null;
    this.uuid = null;
    this.session = {};
    this.blockedEndpoints = {};
    this.cookieJar = new tough.CookieJar();
    this.requestClient = axios.create({
      withCredentials: true,
      httpsAgent: new HttpsCookieAgent({
        cookies: {
          jar: this.cookieJar,
        },
      }),
    });
    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.hostName = 'myt-agg.toyota-europe.com';
    this.brand = 'T';
    this.CLIENT_VERSION = '2.14.0';
    // Updated constants based on Go implementation
    this.CLIENT_SECRET = '6GKIax7fGT5yPHuNmWNVOc4q5POBw1WRSW39ubRA8WPBmQ7MOxhm75EsmKMKENem';
    this.CLIENT_REF_KEY = '3e0b15f6c9c87fbd';
    this.API_VERSION = 'protocol=1.0,resource=2.1';
  }

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  async onReady() {
    // Reset the connection indicator during startup
    this.setState('info.connection', false, true);
    if (this.config.interval < 0.5) {
      this.log.info('Set interval to minimum 0.5');
      this.config.interval = 0.5;
    }
    if (this.config.interval > 2147483647) {
      this.log.info('Set interval to maximum 2147483647');
      this.config.interval = 2147483647;
    }
    this.subscribeStates('*');
    if (this.config.type === 'lexus') {
      this.log.info('Login to Lexus');
      this.brand = 'L';
      this.hostName = 'lexuslink-agg.toyota-europe.com';
    }
    if (!this.config.username || !this.config.password) {
      this.log.error('No username or password set');
      return;
    }
    await this.login();

    if (this.session.access_token && this.uuid) {
      this.log.info('Get Vehicles');
      await this.getDeviceList();
      await this.updateDevices();
      if (this.config.fetchTrips) {
        await this.getHistory();
        this.historyInterval = setInterval(async () => {
          await this.getHistory();
        }, 12 * 60 * 60 * 1000);
      }
      this.updateInterval = setInterval(async () => {
        await this.updateDevices();
      }, this.config.interval * 60 * 1000);

      this.refreshTokenInterval = setInterval(() => {
        this.refreshToken();
      }, 3500 * 1000);
    }
  }

  async login() {
    this.log.info('Login to Toyota');
    const firstResponse = await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/json/realms/root/realms/tme/authenticate?authIndexType=service&authIndexValue=oneapp',
      headers: {
        'x-osname': 'iOS',
        'x-brand': this.brand,
        accept: 'application/json',
        'x-channel': 'ONEAPP',
        brand: this.brand,
        'x-region': 'EU',
        'x-appbrand': this.brand,
        'x-correlationid': 'B10AD742-22D0-4211-8B25-B213BE9A8A00',
        'x-osversion': '16.7.2',
        'accept-language': 'de-DE,de;q=0.9',
        region: 'EU',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'accept-api-version': this.API_VERSION,
        'x-appversion': this.CLIENT_VERSION,
        Cookie: 'route=e8e8b55de08efd3c4b34265c0069d319',
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        return res.data;
      })
      .catch((error) => {
        this.log.error('Failed #1 step');
        this.log.error(error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
      });

    const secondResponse = await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/json/realms/root/realms/tme/authenticate?authIndexType=service&authIndexValue=oneapp',
      headers: {
        'x-appbrand': this.brand,
        'x-osname': 'iOS',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-region': 'EU',
        region: 'EU',
        brand: this.brand,
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-brand': this.brand,
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': 'BDD02A22-CD76-4877-90A9-196EDA5DC695',
        'x-appversion': this.CLIENT_VERSION,
        accept: 'application/json',
        'content-type': 'application/json',
        'accept-api-version': this.API_VERSION,
      },
      data: firstResponse,
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        return res.data;
      })
      .catch((error) => {
        this.log.error('Failed #2 step');
        this.log.error(error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
      });

    if (!secondResponse || !secondResponse.callbacks) {
      this.log.error('No Second Response');
      return;
    }
    secondResponse.callbacks[0].input[0].value = this.config.username;

    const thirdResponse = await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/json/realms/root/realms/tme/authenticate?authIndexType=service&authIndexValue=oneapp',
      headers: {
        'x-appbrand': this.brand,
        'x-osname': 'iOS',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-region': 'EU',
        region: 'EU',
        brand: this.brand,
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-brand': this.brand,
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': 'BDD02A22-CD76-4877-90A9-196EDA5DC695',
        'x-appversion': this.CLIENT_VERSION,
        accept: 'application/json',
        'content-type': 'application/json',
        'accept-api-version': this.API_VERSION,
      },
      data: secondResponse,
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        return res.data;
      })
      .catch((error) => {
        this.log.error('Failed #3 step');
        this.log.error(error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
      });

    if (!thirdResponse || !thirdResponse.callbacks) {
      this.log.error('No Third Response');
      return;
    }

    thirdResponse.callbacks[0].input[0].value = this.config.password;

    const idToken = await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/json/realms/root/realms/tme/authenticate?authIndexType=service&authIndexValue=oneapp',
      headers: {
        'x-appbrand': this.brand,
        'x-osname': 'iOS',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-region': 'EU',
        region: 'EU',
        brand: this.brand,
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-brand': this.brand,
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': 'BDD02A22-CD76-4877-90A9-196EDA5DC695',
        'x-appversion': this.CLIENT_VERSION,
        accept: 'application/json',
        'content-type': 'application/json',
        'accept-api-version': this.API_VERSION,
      },
      data: thirdResponse,
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        return res.data;
      })
      .catch((error) => {
        this.log.error('Failed #4 step');
        this.log.error(error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
      });

    // Updated authorization URL with plain code challenge
    const tokenResponse = await this.requestClient({
      method: 'get',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/oauth2/realms/root/realms/tme/authorize?response_type=code&realm=tme&redirect_uri=com.toyota.oneapp:/oauth2Callback&client_id=oneapp&scope=openid%20profile%20vehicles&code_challenge_method=plain&code_challenge=plain',
      headers: {
        'x-osname': 'iOS',
        'x-brand': this.brand,
        accept: '*/*',
        'x-channel': 'ONEAPP',
        brand: this.brand,
        'x-correlationid': '0F34C246-11F3-4584-AB13-0EA5DA96CB41',
        'x-region': 'EU',
        'x-appbrand': this.brand,
        'x-osversion': '16.7.2',
        'accept-language': 'de-DE,de;q=0.9',
        region: 'EU',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'accept-api-version': this.API_VERSION,
        'x-appversion': this.CLIENT_VERSION,
      },
    })
      .then((res) => {
        this.log.error('Failed code receive step');
        this.log.error(JSON.stringify(res.data));
      })
      .catch((error) => {
        if (error && error.message.includes('Unsupported protocol')) {
          return qs.parse(error.request._options.path.split('?')[1]);
        }
        this.log.error('Failed #5 step');
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });

    if (!tokenResponse || !tokenResponse.code) {
      this.log.error('No Token Response');
      return;
    }

    this.log.info('Start token exchange');
    await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/oauth2/realms/root/realms/tme/access_token',
      headers: {
        'x-appbrand': this.brand,
        'x-osname': 'iOS',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-region': 'EU',
        region: 'EU',
        brand: this.brand,
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-brand': this.brand,
        authorization: 'Basic b25lYXBwOm9uZWFwcA==',
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': 'E422A08C-1A04-415E-BB08-2386EE06CF90',
        'x-appversion': this.CLIENT_VERSION,
        accept: '*/*',
        'content-type': 'application/x-www-form-urlencoded',
        'accept-api-version': this.API_VERSION,
      },
      data: {
        grant_type: 'authorization_code',
        redirect_uri: 'com.toyota.oneapp:/oauth2Callback',
        code: tokenResponse.code,
        code_verifier: 'plain',
        client_id: 'oneapp',
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.id_token) {
          this.log.info('Login successful');
          this.session = res.data;

          this.uuid = jwt.decode(this.session.id_token).uuid;
          this.setState('info.connection', true, true);
        } else {
          this.log.error('Login failed');
        }
      })
      .catch((error) => {
        this.log.error(error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
      });
  }

  async refreshToken() {
    await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/oauth2/realms/root/realms/tme/access_token',
      headers: {
        'x-appbrand': this.brand,
        'x-osname': 'iOS',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-region': 'EU',
        region: 'EU',
        brand: this.brand,
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-brand': this.brand,
        authorization: 'Basic b25lYXBwOm9uZWFwcA==',
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': 'E422A08C-1A04-415E-BB08-2386EE06CF90',
        'x-appversion': this.CLIENT_VERSION,
        accept: '*/*',
        'content-type': 'application/x-www-form-urlencoded',
        'accept-api-version': this.API_VERSION,
      },
      data: {
        grant_type: 'refresh_token',
        redirect_uri: 'com.toyota.oneapp:/oauth2Callback',
        client_id: 'oneapp',
        code_verifier: 'plain',
        refresh_token: this.session.refresh_token,
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.session = res.data;
        this.setState('info.connection', true, true);
      })
      .catch((error) => {
        this.log.error(error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
      });
  }

  async generate_hmac_sha256(key, message) {
    return crypto.createHmac('sha256', key).update(message).digest('hex');
  }

  async getDeviceList() {
    await this.requestClient({
      method: 'get',
      maxBodyLength: Infinity,
      url: 'https://ctpa-oneapi.tceu-ctp-prd.toyotaconnectedeurope.io/v2/vehicle/guid',
      headers: {
        'x-appbrand': this.brand,
        'x-device-timezone': 'CEST',
        'x-osname': 'iOS',
        guid: this.uuid,
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-guid': this.uuid,
        'x-region': 'EU',
        region: 'EU',
        brand: this.brand,
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-locale': 'de-DE',
        'x-brand': this.brand,
        authorization: 'Bearer ' + this.session.access_token,
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': '7683DC30-D4DA-4FEC-850E-F3557A7DCEF4',
        accept: '*/*',
        'x-user-region': 'DE',
        'x-api-key': 'tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF',
        API_KEY: 'tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF',
        // Updated client-ref generation using new key
        'x-client-ref': this.generate_hmac_sha256(this.CLIENT_REF_KEY, this.uuid),
        'x-correlationid': uuidv4(),
        'x-appversion': this.CLIENT_VERSION,
        'x-region': 'EU',
      },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        this.log.info(`Found ${res.data.payload.length} vehicles`);
        if (res.data.payload.length === 0) {
          this.log.warn('Please check if you vehicle is in the new MyToyota App');
          return;
        }
        for (const device of res.data.payload) {
          if (!device.vin) {
            this.log.info(`No VIN found for ${device.deviceTypeName} (${device.alias})`);
            continue;
          }
          await this.cleanOldObjects(device.vin);
          this.deviceArray.push(device.vin);
          const name = device.nickName + ' ' + device.modelName;
          this.log.info('Create vehicle ' + device.vin + ' ' + name);
          await this.extendObjectAsync(device.vin, {
            type: 'device',
            common: {
              name: name,
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(device.vin + '.remote', {
            type: 'channel',
            common: {
              name: 'Remote Controls',
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(device.vin + '.general', {
            type: 'channel',
            common: {
              name: 'General Information',
            },
            native: {},
          });

          const remoteArray = [
            { command: 'climate-control', name: 'True = Start, False = Stop' },
            { command: 'refresh', name: 'Refresh Status' },
            { command: 'door', name: 'True = Lock, False = Unlock' },
          ];
          for (const remote of remoteArray) {
            this.extendObject(device.vin + '.remote.' + remote.command, {
              type: 'state',
              common: {
                name: remote.name || '',
                type: remote.type || 'boolean',
                role: remote.role || 'switch',
                def: remote.def == null ? false : remote.def,
                states: remote.states,
                write: true,
                read: true,
              },
              native: {},
            });
          }
          this.json2iob.parse(device.vin + '.general', device);
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  // ...existing code...
  async cleanOldObjects(vin) {
    const remoteState = await this.getObjectAsync(vin + '.addtionalInfo');
    if (remoteState) {
      this.log.info('clean old states ' + vin);
      await this.delObjectAsync(vin, { recursive: true });
    }
  }

  async updateDevices() {
    const statusArray = [
      {
        path: 'status',
        url: 'https://ctpa-oneapi.tceu-ctp-prd.toyotaconnectedeurope.io/v1/global/remote/status',
        desc: 'Status of the car',
      },
      {
        path: 'telemetry',
        url: 'https://ctpa-oneapi.tceu-ctp-prd.toyotaconnectedeurope.io/v3/telemetry',
        desc: 'Telemetry of the car',
      },
      {
        path: 'climate',
        url: 'https://ctpa-oneapi.tceu-ctp-prd.toyotaconnectedeurope.io/v1/global/remote/climate-status',
        desc: 'Climate of the car',
      },
    ];

    const headers = {
      'x-appbrand': this.brand,
      'x-device-timezone': 'CEST',
      'x-osname': 'iOS',
      guid: this.uuid,
      'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
      'x-guid': this.uuid,
      'x-region': 'EU',
      region: 'EU',
      brand: this.brand,
      'x-channel': 'ONEAPP',
      'x-osversion': '16.7.2',
      'x-locale': 'de-DE',
      'x-brand': this.brand,
      authorization: 'Bearer ' + this.session.access_token,
      'accept-language': 'de-DE,de;q=0.9',
      'x-correlationid': '7683DC30-D4DA-4FEC-850E-F3557A7DCEF4',
      accept: '*/*',
      'x-user-region': 'DE',
      'x-api-key': 'tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF',
      API_KEY: 'tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF',
      // Updated client-ref generation using new key
      'x-client-ref': this.generate_hmac_sha256(this.CLIENT_REF_KEY, this.uuid),
      'x-correlationid': uuidv4(),
      'x-appversion': this.CLIENT_VERSION,
      'x-region': 'EU',
    };
    for (const vin of this.deviceArray) {
      for (const element of statusArray) {
        if (this.blockedEndpoints[vin] && this.blockedEndpoints[vin].includes(element.path)) {
          continue;
        }
        const url = element.url.replace('$vin', vin);
        headers.vin = vin;

        await this.requestClient({
          method: 'get',
          url: url,
          headers: headers,
        })
          .then((res) => {
            this.log.debug(JSON.stringify(res.data));
            if (!res.data) {
              return;
            }
            const data = res.data.payload;

            const forceIndex = null;
            const preferedArrayName = null;

            this.json2iob.parse(vin + '.' + element.path, data, {
              forceIndex: forceIndex,
              preferedArrayName: preferedArrayName,
              channelName: element.desc,
            });
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401 || error.response.status === 403) {
                error.response && this.log.debug(JSON.stringify(error.response.data));
                this.log.info(element.path + ' receive 401/403 error. Relogin in 5 minutes');
                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                this.refreshTokenTimeout = setTimeout(() => {
                  this.login();
                }, 1000 * 60 * 5);

                return;
              }
              if (error.response.status >= 500) {
                this.log.warn(JSON.stringify(error.response.data));
                this.log.info(element.path + ' receive 500 error. Skip until restart');
                this.blockedEndpoints[vin] = this.blockedEndpoints[vin] || [];
                this.blockedEndpoints[vin].push(element.path);
                return;
              }
            }
            this.log.error(url);
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      }
    }
  }

  async getHistory() {
    const statusArray = [
      {
        path: 'trips',
        url:
          'https://ctpa-oneapi.tceu-ctp-prd.toyotaconnectedeurope.io/v1/trips?from=2023-01-01&limit=5&offset=0&route=true&summary=true&to=' +
          new Date().toISOString().split('T')[0],
        desc: 'Trips of the car',
      },
    ];

    const headers = {
      'x-appbrand': this.brand,
      'x-device-timezone': 'CEST',
      'x-osname': 'iOS',
      guid: this.uuid,
      'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
      'x-guid': this.uuid,
      'x-region': 'EU',
      region: 'EU',
      brand: this.brand,
      'x-channel': 'ONEAPP',
      'x-osversion': '16.7.2',
      'x-locale': 'de-DE',
      'x-brand': this.brand,
      authorization: 'Bearer ' + this.session.access_token,
      'accept-language': 'de-DE,de;q=0.9',
      'x-correlationid': '7683DC30-D4DA-4FEC-850E-F3557A7DCEF4',
      accept: '*/*',
      'x-user-region': 'DE',
      'x-api-key': 'tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF',
      API_KEY: 'tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF',
      // Updated client-ref generation using new key
      'x-client-ref': this.generate_hmac_sha256(this.CLIENT_REF_KEY, this.uuid),
      'x-correlationid': uuidv4(),
      'x-appversion': this.CLIENT_VERSION,
      'x-region': 'EU',
    };
    for (const vin of this.deviceArray) {
      statusArray.forEach(async (element) => {
        const url = element.url.replace('$vin', vin);
        headers.vin = vin;

        await this.requestClient({
          method: 'get',
          url: url,
          headers: headers,
        })
          .then((res) => {
            this.log.debug(JSON.stringify(res.data));
            if (!res.data) {
              return;
            }
            const data = res.data.payload;
            for (const trip of data.trips) {
              delete trip.route;
            }
            for (const summary of data.summary) {
              delete summary.histograms;
            }
            this.json2iob.parse(vin + '.' + element.path, data, {
              forceIndex: true,
              channelName: element.desc,
            });
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401 || error.response.status === 403) {
                error.response && this.log.debug(JSON.stringify(error.response.data));
                this.log.info(element.path + ' receive 401/403 error. Relogin in 5 minutes');
                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                this.refreshTokenTimeout = setTimeout(() => {
                  this.login();
                }, 1000 * 60 * 5);

                return;
              }
            }
            this.log.error(url);
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      });
    }
  }

  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  onUnload(callback) {
    try {
      this.setState('info.connection', false, true);
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
      callback();
    } catch (e) {
      callback();
    }
  }

  /**
   * Is called if a subscribed state changes
   * @param {string} id
   * @param {ioBroker.State | null | undefined} state
   */
  async onStateChange(id, state) {
    if (state) {
      if (!state.ack) {
        if (id.split('.')[3] !== 'remote') {
          return;
        }
        const deviceId = id.split('.')[2];
        const path = id.split('.')[4];
        if (path === 'refresh') {
          this.updateDevices();
          return;
        }
        const data = {};
        let url = 'https://ctpa-oneapi.tceu-ctp-prd.toyotaconnectedeurope.io/v1/global/remote/command';
        if (path === 'climate-control') {
          url = 'https://ctpa-oneapi.tceu-ctp-prd.toyotaconnectedeurope.io/v1/global/remote/climate-control';
          data.command = state.val ? 'engine-start' : 'engine-stop';
        }
        if (path === 'door') {
          data.command = state.val ? 'door-lock' : 'door-unlock';
        }

        this.log.debug(JSON.stringify(data));
        this.log.debug(url);
        await this.requestClient({
          method: 'post',
          url: url,
          headers: {
            'x-appbrand': this.brand,
            'x-device-timezone': 'CEST',
            'x-osname': 'iOS',
            guid: this.uuid,
            'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
            'x-guid': this.uuid,
            'x-region': 'EU',
            region: 'EU',
            brand: this.brand,
            'x-channel': 'ONEAPP',
            vin: deviceId,
            'x-osversion': '16.7.2',
            'x-locale': 'de-DE',
            'x-brand': this.brand,
            authorization: 'Bearer ' + this.session.access_token,
            'accept-language': 'de-DE,de;q=0.9',
            'x-correlationid': 'D7F048C1-F0A1-4920-AA37-264C8A1FB4A3',
            accept: '*/*',
            'x-user-region': 'DE',
            'x-api-key': 'tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF',
            API_KEY: 'tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF',
            // Updated client-ref generation using new key
            'x-client-ref': this.generate_hmac_sha256(this.CLIENT_REF_KEY, this.uuid),
            'x-correlationid': uuidv4(),
            'x-appversion': this.CLIENT_VERSION,
            'x-region': 'EU',
          },
          data: data,
        })
          .then((res) => {
            this.log.debug(JSON.stringify(res.data));
            return res.data;
          })
          .catch((error) => {
            this.log.error(error);
            if (error.response) {
              this.log.error(JSON.stringify(error.response.data));
            }
          });
        this.refreshTimeout && clearTimeout(this.refreshTimeout);
        this.refreshTimeout = setTimeout(async () => {
          await this.updateDevices();
        }, 20 * 1000);
      }
    }
  }
}

if (require.main !== module) {
  // Export the constructor in compact mode
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  module.exports = (options) => new Toyota(options);
} else {
  // otherwise start the instance directly
  new Toyota();
}
