"use strict";

/*
 * Created with @iobroker/create-adapter v2.0.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios");
const Json2iob = require("./lib/json2iob");

class Toyota extends utils.Adapter {
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: "toyota",
        });
        this.on("ready", this.onReady.bind(this));
        //   this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));
        this.deviceArray = [];
        this.json2iob = new Json2iob(this);
        this.token = null;
        this.uuid = null;
        this.requestClient = axios.create();
        this.updateInterval = null;
        this.reLoginTimeout = null;
        this.refreshTokenTimeout = null;
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Reset the connection indicator during startup
        this.setState("info.connection", false, true);
        if (this.config.interval < 0.5) {
            this.log.info("Set interval to minimum 0.5");
            this.config.interval = 0.5;
        }
        //this.subscribeStates("*");

        await this.login();

        if (this.token && this.uuid) {
            await this.getDeviceList();
            await this.updateDevices();
            this.updateInterval = setInterval(async () => {
                await this.updateDevices();
            }, this.config.interval * 60 * 1000);
            this.refreshTokenInterval = setInterval(() => {
                this.login();
            }, 3500 * 1000);
        }
    }
    async login() {
        this.session_data = await this.requestClient({
            method: "post",
            url: "https://myt-agg.toyota-europe.com/cma/api/user/login",
            headers: {
                accept: "*/*",
                "content-type": "application/json",
                "x-tme-locale": "en-gb",
                "x-tme-brand": "TOYOTA",
                "x-tme-app-version": "4.5.0",
                "user-agent": "MyT/4.5.0 iPhone10,5 iOS/14.8 CFNetwork/1240.0.4 Darwin/20.6.0",
                "accept-language": "de-DE",
            },
            data: JSON.stringify({
                password: this.config.password,
                username: this.config.username,
            }),
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.token = res.data.token;
                if (res.data.customerProfile) {
                    this.uuid = res.data.customerProfile.uuid;
                } else {
                    this.log.error("No uuid found");
                }
                this.setState("info.connection", true, true);
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
            method: "get",
            url: "https://myt-agg.toyota-europe.com/cma/api/user/" + this.uuid + "/vehicle/details",
            headers: {
                cookie: "iPlanetDirectoryPro=" + this.token,
                accept: "*/*",
                "x-tme-locale": "de-de",
                "x-tme-app-version": "4.5.0",
                "user-agent": "MyT/4.5.0 iPhone10,5 iOS/14.8 CFNetwork/1240.0.4 Darwin/20.6.0",
                "accept-language": "de-DE",
                "x-tme-brand": "TOYOTA",
            },
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));

                for (const device of res.data) {
                    this.deviceArray.push(device.vin);
                    const name = device.alias;
                    await this.setObjectNotExistsAsync(device.vin, {
                        type: "device",
                        common: {
                            name: name,
                        },
                        native: {},
                    });

                    await this.setObjectNotExistsAsync(device.vin + ".general", {
                        type: "channel",
                        common: {
                            name: "General Information",
                        },
                        native: {},
                    });

                    this.json2iob.parse(device.vin + ".general", device);
                }
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    async updateDevices() {
        const statusArray = [
            {
                path: "status",
                url: "https://myt-agg.toyota-europe.com/cma/api/users/" + this.uuid + "/vehicles/$vin/vehicleStatus",
                desc: "Status of the car",
            },
            {
                path: "addtionalInfo",
                url: "https://myt-agg.toyota-europe.com/cma/api/vehicle/$vin/addtionalInfo",
                desc: "AddtionalInfo of the car",
            },
            {
                path: "remoteControlStatus",
                url: "https://myt-agg.toyota-europe.com/cma/api/vehicles/$vin/remoteControl/status",
                desc: "remoteControlStatus of the car",
            },
            {
                path: "location",
                url: "https://myt-agg.toyota-europe.com/cma/api/users/" + this.uuid + "/vehicle/location",
                desc: "Location of the car",
            },
        ];

        this.deviceArray.forEach(async (vin) => {
            statusArray.forEach(async (element) => {
                const url = element.url.replace("$vin", vin);
                const headers = {
                    cookie: "iPlanetDirectoryPro=" + this.token,
                    accept: "*/*",
                    "x-tme-locale": "de-de",
                    vin: vin,
                    uuid: this.uuid,
                    "x-tme-app-version": "4.5.0",
                    "user-agent": "MyT/4.5.0 iPhone10,5 iOS/14.8 CFNetwork/1240.0.4 Darwin/20.6.0",
                    "accept-language": "de-DE",
                    "x-tme-brand": "TOYOTA",
                };
                await this.requestClient({
                    method: "get",
                    url: url,
                    headers: headers,
                })
                    .then((res) => {
                        this.log.debug(JSON.stringify(res.data));
                        if (!res.data) {
                            return;
                        }
                        const data = res.data;

                        const forceIndex = null;
                        const preferedArrayName = null;

                        this.json2iob.parse(vin + "." + element.path, data, { forceIndex: forceIndex, preferedArrayName: preferedArrayName, channelName: element.desc });
                    })
                    .catch((error) => {
                        if (error.response) {
                            if (error.response.status === 401 || error.response.status === 403) {
                                error.response && this.log.debug(JSON.stringify(error.response.data));
                                this.log.info(element.path + " receive 401/403 error. Relogin in 5 minutes");
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
        });
    }

    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    onUnload(callback) {
        try {
            this.setState("info.connection", false, true);
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
