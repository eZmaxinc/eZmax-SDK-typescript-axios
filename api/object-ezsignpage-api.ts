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
import { CommonResponseError } from '../model';
// @ts-ignore
import { EzsignpageConsultV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignpageApi - axios parameter creator
 * @export
 */
export const ObjectEzsignpageApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Consult an Ezsignpage
         * @param {number} pkiEzsignpageID 
         * @param {object} body 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignpageConsultV1: async (pkiEzsignpageID: number, body: object, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignpageID' is not null or undefined
            assertParamExists('ezsignpageConsultV1', 'pkiEzsignpageID', pkiEzsignpageID)
            // verify required parameter 'body' is not null or undefined
            assertParamExists('ezsignpageConsultV1', 'body', body)
            const localVarPath = `/1/object/ezsignpage/{pkiEzsignpageID}/consult`
                .replace(`{${"pkiEzsignpageID"}}`, encodeURIComponent(String(pkiEzsignpageID)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(body, localVarRequestOptions, configuration)

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
 * ObjectEzsignpageApi - functional programming interface
 * @export
 */
export const ObjectEzsignpageApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignpageApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Consult an Ezsignpage
         * @param {number} pkiEzsignpageID 
         * @param {object} body 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignpageConsultV1(pkiEzsignpageID: number, body: object, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignpageConsultV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignpageConsultV1(pkiEzsignpageID, body, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectEzsignpageApi - factory interface
 * @export
 */
export const ObjectEzsignpageApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignpageApiFp(configuration)
    return {
        /**
         * 
         * @summary Consult an Ezsignpage
         * @param {number} pkiEzsignpageID 
         * @param {object} body 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignpageConsultV1(pkiEzsignpageID: number, body: object, options?: any): AxiosPromise<EzsignpageConsultV1Response> {
            return localVarFp.ezsignpageConsultV1(pkiEzsignpageID, body, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignpageApi - object-oriented interface
 * @export
 * @class ObjectEzsignpageApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignpageApi extends BaseAPI {
    /**
     * 
     * @summary Consult an Ezsignpage
     * @param {number} pkiEzsignpageID 
     * @param {object} body 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignpageApi
     */
    public ezsignpageConsultV1(pkiEzsignpageID: number, body: object, options?: AxiosRequestConfig) {
        return ObjectEzsignpageApiFp(this.configuration).ezsignpageConsultV1(pkiEzsignpageID, body, options).then((request) => request(this.axios, this.basePath));
    }
}
