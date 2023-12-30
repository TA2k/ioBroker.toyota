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
      // await this.getHistory();
      this.updateInterval = setInterval(async () => {
        await this.updateDevices();
      }, this.config.interval * 60 * 1000);
      // this.historyInterval = setInterval(async () => {
      //   await this.getHistory();
      // }, 12 * 60 * 60 * 1000);
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
        accept: '*/*',
        'x-channel': 'ONEAPP',
        brand: 'T',
        'x-region': 'EU',
        'x-appbrand': 'T',
        'x-correlationid': 'B10AD742-22D0-4211-8B25-B213BE9A8A00',
        'x-osversion': '16.7.2',
        'accept-language': 'de-DE,de;q=0.9',
        region: 'EU',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'accept-api-version': 'resource=2.0, protocol=1.0',
        'x-appversion': '2.4.2',
        Cookie: 'route=e8e8b55de08efd3c4b34265c0069d319',
      },
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
    const secondResponse = await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/json/realms/root/realms/tme/authenticate?authIndexType=service&authIndexValue=oneapp',
      headers: {
        'x-appbrand': 'T',
        'x-osname': 'iOS',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-region': 'EU',
        region: 'EU',
        brand: 'T',
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-brand': this.brand,
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': 'BDD02A22-CD76-4877-90A9-196EDA5DC695',
        'x-appversion': '2.4.2',
        accept: '*/*',
        'content-type': 'application/json',
        'accept-api-version': 'resource=2.0, protocol=1.0',
      },
      data: firstResponse,
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
    secondResponse.callbacks[0].input[0].value = this.config.username;
    const thirdResponse = await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/json/realms/root/realms/tme/authenticate?authIndexType=service&authIndexValue=oneapp',
      headers: {
        'x-appbrand': 'T',
        'x-osname': 'iOS',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-region': 'EU',
        region: 'EU',
        brand: 'T',
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-brand': this.brand,
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': 'BDD02A22-CD76-4877-90A9-196EDA5DC695',
        'x-appversion': '2.4.2',
        accept: '*/*',
        'content-type': 'application/json',
        'accept-api-version': 'resource=2.0, protocol=1.0',
      },
      data: secondResponse,
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
    thirdResponse.callbacks[0].input[0].value = this.config.password;
    const idToken = await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/json/realms/root/realms/tme/authenticate?authIndexType=service&authIndexValue=oneapp',
      headers: {
        'x-appbrand': 'T',
        'x-osname': 'iOS',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-region': 'EU',
        region: 'EU',
        brand: 'T',
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-brand': this.brand,
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': 'BDD02A22-CD76-4877-90A9-196EDA5DC695',
        'x-appversion': '2.4.2',
        accept: '*/*',
        'content-type': 'application/json',
        'accept-api-version': 'resource=2.0, protocol=1.0',
      },
      data: thirdResponse,
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

    const tokenResponse = await this.requestClient({
      method: 'get',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/oauth2/realms/root/realms/tme/authorize?response_type=code&realm=tme&redirect_uri=com.toyota.oneapp:/oauth2Callback&client_id=oneapp&scope=openid%20profile%20write&code_challenge_method=S256&code_challenge=Bx88SxgIEnvxrsobwijnUlzg3rrb-zNV4wzDlndWFVc',
      headers: {
        'x-osname': 'iOS',
        'x-brand': this.brand,
        accept: '*/*',
        'x-channel': 'ONEAPP',
        brand: 'T',
        'x-correlationid': '0F34C246-11F3-4584-AB13-0EA5DA96CB41',
        'x-region': 'EU',
        'x-appbrand': 'T',
        'x-osversion': '16.7.2',
        'accept-language': 'de-DE,de;q=0.9',
        region: 'EU',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'accept-api-version': 'resource=2.0, protocol=1.0',
        'x-appversion': '2.4.2',
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        return res.data;
      })
      .catch((error) => {
        if (error && error.message.includes('Unsupported protocol')) {
          return qs.parse(error.request._options.path.split('?')[1]);
        }
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
    await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://b2c-login.toyota-europe.com/oauth2/realms/root/realms/tme/access_token',
      headers: {
        'x-appbrand': 'T',
        'x-osname': 'iOS',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-region': 'EU',
        region: 'EU',
        brand: 'T',
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-brand': this.brand,
        authorization: 'Basic b25lYXBwOm9uZWFwcA==',
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': 'E422A08C-1A04-415E-BB08-2386EE06CF90',
        'x-appversion': '2.4.2',
        accept: '*/*',
        'content-type': 'application/x-www-form-urlencoded',
        'accept-api-version': 'resource=2.0, protocol=1.0',
      },
      data: {
        grant_type: 'authorization_code',
        redirect_uri: 'com.toyota.oneapp:/oauth2Callback',
        code: tokenResponse.code,
        code_verifier: 'tsY5-j-ZLYxNVnmz6wmJ9PTm2Ly7QpfXcQnhyU09Pog',
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
        'x-appbrand': 'T',
        'x-osname': 'iOS',
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-region': 'EU',
        region: 'EU',
        brand: 'T',
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-brand': this.brand,
        authorization: 'Basic b25lYXBwOm9uZWFwcA==',
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': 'E422A08C-1A04-415E-BB08-2386EE06CF90',
        'x-appversion': '2.4.2',
        accept: '*/*',
        'content-type': 'application/x-www-form-urlencoded',
        'accept-api-version': 'resource=2.0, protocol=1.0',
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
  async getDeviceList() {
    await this.requestClient({
      method: 'get',
      maxBodyLength: Infinity,
      url: 'https://ctpa-oneapi.tceu-ctp-prd.toyotaconnectedeurope.io/v2/vehicle/guid',
      headers: {
        'x-appbrand': 'T',
        'x-device-timezone': 'CEST',
        'x-osname': 'iOS',
        guid: this.uuid,
        'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
        'x-guid': this.uuid,
        'x-region': 'EU',
        region: 'EU',
        brand: 'T',
        'x-channel': 'ONEAPP',
        'x-osversion': '16.7.2',
        'x-locale': 'de-DE',
        'x-brand': this.brand,
        authorization: 'Bearer ' + this.session.access_token,
        'accept-language': 'de-DE,de;q=0.9',
        'x-correlationid': '7683DC30-D4DA-4FEC-850E-F3557A7DCEF4',
        'x-appversion': '2.4.2',
        accept: '*/*',
        'x-user-region': 'DE',
        'x-api-key': 'tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF',
      },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        this.log.info(`Found ${res.data.payload.length} vehicles`);
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
            // { command: 'hvac', name: 'True = Start, False = Stop' },
            // { command: 'hvac-temperature', name: 'HVAC Temperature', type: 'number', role: 'value', def: 22 },
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
  async cleanOldObjects(vin) {
    const remoteState = await this.getObjectAsync(vin + '.statusV2');
    if (remoteState) {
      this.log.debug('clean old states' + vin);
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
    ];

    const headers = {
      'x-appbrand': 'T',
      'x-device-timezone': 'CEST',
      'x-osname': 'iOS',

      guid: this.uuid,
      'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
      'x-guid': this.uuid,
      'x-region': 'EU',
      region: 'EU',
      brand: 'T',
      'x-channel': 'ONEAPP',
      'x-osversion': '16.7.2',
      'x-locale': 'de-DE',
      'x-brand': this.brand,
      authorization: 'Bearer ' + this.session.access_token,
      'accept-language': 'de-DE,de;q=0.9',
      'x-correlationid': '7683DC30-D4DA-4FEC-850E-F3557A7DCEF4',
      'x-appversion': '2.4.2',
      accept: '*/*',
      'x-user-region': 'DE',
      'x-api-key': 'tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF',
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
            }
            this.log.error(url);
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      });
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
      'x-appbrand': 'T',
      'x-device-timezone': 'CEST',
      'x-osname': 'iOS',

      guid: this.uuid,
      'user-agent': 'Toyota/134 CFNetwork/1410.0.3 Darwin/22.6.0',
      'x-guid': this.uuid,
      'x-region': 'EU',
      region: 'EU',
      brand: 'T',
      'x-channel': 'ONEAPP',
      'x-osversion': '16.7.2',
      'x-locale': 'de-DE',
      'x-brand': this.brand,
      authorization: 'Bearer ' + this.session.access_token,
      'accept-language': 'de-DE,de;q=0.9',
      'x-correlationid': '7683DC30-D4DA-4FEC-850E-F3557A7DCEF4',
      'x-appversion': '2.4.2',
      accept: '*/*',
      'x-user-region': 'DE',
      'x-api-key': 'tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF',
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
        if (path === 'hvac-temperature') {
          return;
        }
        const hvacTemperatureState = await this.getStateAsync(deviceId + '.remote.hvac-temperature');
        let hvacTemperature = 22;
        if (hvacTemperatureState) {
          hvacTemperature = hvacTemperatureState.val;
        }

        const data = {
          RemoteHvac: {
            Option: {
              RearDefogger: 0,
              FrontDefogger: 0,
            },
            Sw: state.val ? 1 : 0,
            Temperature: {
              TemperatureUnit: 1,
              SettingType: 0,
              SettingTemperature: hvacTemperature,
            },
          },
        };
        const url = 'https://' + this.hostName + '/cma/api/user/' + this.uuid + '/vehicle/' + deviceId + '/remoteControl';
        this.log.debug(JSON.stringify(data));
        this.log.debug(url);
        await this.requestClient({
          method: 'post',
          url: url,
          headers: {
            cookie: 'iPlanetDirectoryPro=' + this.token,
            accept: '*/*',
            'x-tme-locale': 'de-de',
            'x-tme-app-version': '4.18.1',
            'user-agent': 'MyT/4.18.1 iPhone10,5 iOS/14.8 CFNetwork/1240.0.4 Darwin/20.6.0',
            'accept-language': 'de-DE',
            'x-tme-brand': this.brand,
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
        }, 10 * 1000);
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
