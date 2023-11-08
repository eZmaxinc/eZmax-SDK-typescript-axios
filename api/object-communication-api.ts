/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import type { Configuration } from '../configuration';
import type { AxiosPromise, AxiosInstance, AxiosRequestConfig } from 'axios';
import globalAxios from 'axios';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { CommunicationSendV1Request } from '../model';
// @ts-ignore
import { CommunicationSendV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectCommunicationApi - axios parameter creator
 * @export
 */
export const ObjectCommunicationApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to send one or many elements at once.
         * @summary Send a new Communication
         * @param {CommunicationSendV1Request} communicationSendV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        communicationSendV1: async (communicationSendV1Request: CommunicationSendV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'communicationSendV1Request' is not null or undefined
            assertParamExists('communicationSendV1', 'communicationSendV1Request', communicationSendV1Request)
            const localVarPath = `/1/object/communication/send`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'POST', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(communicationSendV1Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
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
 * ObjectCommunicationApi - functional programming interface
 * @export
 */
export const ObjectCommunicationApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectCommunicationApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to send one or many elements at once.
         * @summary Send a new Communication
         * @param {CommunicationSendV1Request} communicationSendV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async communicationSendV1(communicationSendV1Request: CommunicationSendV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommunicationSendV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.communicationSendV1(communicationSendV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectCommunicationApi - factory interface
 * @export
 */
export const ObjectCommunicationApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectCommunicationApiFp(configuration)
    return {
        /**
         * The endpoint allows to send one or many elements at once.
         * @summary Send a new Communication
         * @param {CommunicationSendV1Request} communicationSendV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        communicationSendV1(communicationSendV1Request: CommunicationSendV1Request, options?: any): AxiosPromise<CommunicationSendV1Response> {
            return localVarFp.communicationSendV1(communicationSendV1Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectCommunicationApi - object-oriented interface
 * @export
 * @class ObjectCommunicationApi
 * @extends {BaseAPI}
 */
export class ObjectCommunicationApi extends BaseAPI {
    /**
     * The endpoint allows to send one or many elements at once.
     * @summary Send a new Communication
     * @param {CommunicationSendV1Request} communicationSendV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectCommunicationApi
     */
    public communicationSendV1(communicationSendV1Request: CommunicationSendV1Request, options?: AxiosRequestConfig) {
        return ObjectCommunicationApiFp(this.configuration).communicationSendV1(communicationSendV1Request, options).then((request) => request(this.axios, this.basePath));
    }
}
