/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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
import { CommonResponseError } from '../model';
// @ts-ignore
import { CommunicationGetObjectV2Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectCommunicationApi - axios parameter creator
 * @export
 */
export const ObjectCommunicationApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Retrieve an existing Communication
         * @param {number} pkiCommunicationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        communicationGetObjectV2: async (pkiCommunicationID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiCommunicationID' is not null or undefined
            assertParamExists('communicationGetObjectV2', 'pkiCommunicationID', pkiCommunicationID)
            const localVarPath = `/2/object/communication/{pkiCommunicationID}`
                .replace(`{${"pkiCommunicationID"}}`, encodeURIComponent(String(pkiCommunicationID)));
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
 * ObjectCommunicationApi - functional programming interface
 * @export
 */
export const ObjectCommunicationApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectCommunicationApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Retrieve an existing Communication
         * @param {number} pkiCommunicationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async communicationGetObjectV2(pkiCommunicationID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<CommunicationGetObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.communicationGetObjectV2(pkiCommunicationID, options);
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
         * 
         * @summary Retrieve an existing Communication
         * @param {number} pkiCommunicationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        communicationGetObjectV2(pkiCommunicationID: number, options?: any): AxiosPromise<CommunicationGetObjectV2Response> {
            return localVarFp.communicationGetObjectV2(pkiCommunicationID, options).then((request) => request(axios, basePath));
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
     * 
     * @summary Retrieve an existing Communication
     * @param {number} pkiCommunicationID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectCommunicationApi
     */
    public communicationGetObjectV2(pkiCommunicationID: number, options?: AxiosRequestConfig) {
        return ObjectCommunicationApiFp(this.configuration).communicationGetObjectV2(pkiCommunicationID, options).then((request) => request(this.axios, this.basePath));
    }
}
