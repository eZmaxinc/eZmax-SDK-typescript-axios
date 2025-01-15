/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import type { Configuration } from '../configuration';
import type { AxiosPromise, AxiosInstance, RawAxiosRequestConfig } from 'axios';
import globalAxios from 'axios';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, type RequestArgs, BaseAPI, RequiredError, operationServerMap } from '../base';
// @ts-ignore
import type { CommonResponseError } from '../model';
// @ts-ignore
import type { GlobalCustomerGetEndpointV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * GlobalCustomerApi - axios parameter creator
 * @export
 */
export const GlobalCustomerApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
         * @summary Get customer endpoint
         * @param {string} pksCustomerCode 
         * @param {GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        globalCustomerGetEndpointV1: async (pksCustomerCode: string, sInfrastructureproductCode?: GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pksCustomerCode' is not null or undefined
            assertParamExists('globalCustomerGetEndpointV1', 'pksCustomerCode', pksCustomerCode)
            const localVarPath = `/1/customer/{pksCustomerCode}/endpoint`
                .replace(`{${"pksCustomerCode"}}`, encodeURIComponent(String(pksCustomerCode)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            //const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'GET', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            if (sInfrastructureproductCode !== undefined) {
                localVarQueryParameter['sInfrastructureproductCode'] = sInfrastructureproductCode;
            }


    
            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
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
 * GlobalCustomerApi - functional programming interface
 * @export
 */
export const GlobalCustomerApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = GlobalCustomerApiAxiosParamCreator(configuration)
    return {
        /**
         * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
         * @summary Get customer endpoint
         * @param {string} pksCustomerCode 
         * @param {GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        async globalCustomerGetEndpointV1(pksCustomerCode: string, sInfrastructureproductCode?: GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GlobalCustomerGetEndpointV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['GlobalCustomerApi.globalCustomerGetEndpointV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * GlobalCustomerApi - factory interface
 * @export
 */
export const GlobalCustomerApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = GlobalCustomerApiFp(configuration)
    return {
        /**
         * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
         * @summary Get customer endpoint
         * @param {string} pksCustomerCode 
         * @param {GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        globalCustomerGetEndpointV1(pksCustomerCode: string, sInfrastructureproductCode?: GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum, options?: RawAxiosRequestConfig): AxiosPromise<GlobalCustomerGetEndpointV1Response> {
            return localVarFp.globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * GlobalCustomerApi - object-oriented interface
 * @export
 * @class GlobalCustomerApi
 * @extends {BaseAPI}
 */
export class GlobalCustomerApi extends BaseAPI {
    /**
     * Retrieve the customer\'s specific server endpoint where to send requests. This will help locate the proper region (ie: sInfrastructureregionCode) and the proper environment (ie: sInfrastructureenvironmenttypeDescription) where the customer\'s data is stored.
     * @summary Get customer endpoint
     * @param {string} pksCustomerCode 
     * @param {GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
     * @param {*} [options] Override http request option.
     * @deprecated
     * @throws {RequiredError}
     * @memberof GlobalCustomerApi
     */
    public globalCustomerGetEndpointV1(pksCustomerCode: string, sInfrastructureproductCode?: GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum, options?: RawAxiosRequestConfig) {
        return GlobalCustomerApiFp(this.configuration).globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum = {
    appcluster01: 'appcluster01',
    ezsignuser: 'ezsignuser'
} as const;
export type GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum = typeof GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum[keyof typeof GlobalCustomerGetEndpointV1SInfrastructureproductCodeEnum];
