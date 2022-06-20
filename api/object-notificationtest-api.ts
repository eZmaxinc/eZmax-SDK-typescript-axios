/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import globalAxios, { AxiosPromise, AxiosInstance, AxiosRequestConfig } from 'axios';
import { Configuration } from '../configuration';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { NotificationtestGetElementsV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectNotificationtestApi - axios parameter creator
 * @export
 */
export const ObjectNotificationtestApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Retrieve an existing Notificationtest\'s Elements
         * @param {number} pkiNotificationtestID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        notificationtestGetElementsV1: async (pkiNotificationtestID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiNotificationtestID' is not null or undefined
            assertParamExists('notificationtestGetElementsV1', 'pkiNotificationtestID', pkiNotificationtestID)
            const localVarPath = `/1/object/notificationtest/{pkiNotificationtestID}/getElements`
                .replace(`{${"pkiNotificationtestID"}}`, encodeURIComponent(String(pkiNotificationtestID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'GET', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'GET' as string,
                        url: basePath + toPathString(localVarUrlObj) as string,
                        body: localVarRequestOptions.data || '' as string
                    }
                    const signatureHeaders = RequestSignature.getHeaders(headers)
                    localVarRequestOptions.headers = { ...localVarRequestOptions.headers, ...signatureHeaders }
                } 
            }

            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
    }
};

/**
 * ObjectNotificationtestApi - functional programming interface
 * @export
 */
export const ObjectNotificationtestApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectNotificationtestApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Retrieve an existing Notificationtest\'s Elements
         * @param {number} pkiNotificationtestID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async notificationtestGetElementsV1(pkiNotificationtestID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<NotificationtestGetElementsV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.notificationtestGetElementsV1(pkiNotificationtestID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectNotificationtestApi - factory interface
 * @export
 */
export const ObjectNotificationtestApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectNotificationtestApiFp(configuration)
    return {
        /**
         * 
         * @summary Retrieve an existing Notificationtest\'s Elements
         * @param {number} pkiNotificationtestID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        notificationtestGetElementsV1(pkiNotificationtestID: number, options?: any): AxiosPromise<NotificationtestGetElementsV1Response> {
            return localVarFp.notificationtestGetElementsV1(pkiNotificationtestID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectNotificationtestApi - object-oriented interface
 * @export
 * @class ObjectNotificationtestApi
 * @extends {BaseAPI}
 */
export class ObjectNotificationtestApi extends BaseAPI {
    /**
     * 
     * @summary Retrieve an existing Notificationtest\'s Elements
     * @param {number} pkiNotificationtestID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectNotificationtestApi
     */
    public notificationtestGetElementsV1(pkiNotificationtestID: number, options?: AxiosRequestConfig) {
        return ObjectNotificationtestApiFp(this.configuration).notificationtestGetElementsV1(pkiNotificationtestID, options).then((request) => request(this.axios, this.basePath));
    }
}