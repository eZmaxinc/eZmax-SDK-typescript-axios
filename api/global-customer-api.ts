/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.35
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import globalAxios, { AxiosPromise, AxiosInstance } from 'axios';
import { Configuration } from '../configuration';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { GlobalCustomerGetEndpointV1Response } from '../model';
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
         * @param {string} pksCustomerCode The customer code assigned to your account
         * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        globalCustomerGetEndpointV1: async (pksCustomerCode: string, sInfrastructureproductCode?: 'appcluster01' | 'ezsignuser', options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pksCustomerCode' is not null or undefined
            assertParamExists('globalCustomerGetEndpointV1', 'pksCustomerCode', pksCustomerCode)
            const localVarPath = `/1/customer/{pksCustomerCode}/endpoint`
                .replace(`{${"pksCustomerCode"}}`, encodeURIComponent(String(pksCustomerCode)));
            
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

            if (sInfrastructureproductCode !== undefined) {
                localVarQueryParameter['sInfrastructureproductCode'] = sInfrastructureproductCode;
            }


    
            setSearchParams(localVarUrlObj, localVarQueryParameter, options.query);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'GET' as string,
                        url: basePath + localVarPath as string,
                        body: localVarRequestOptions.data as string
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
         * @param {string} pksCustomerCode The customer code assigned to your account
         * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async globalCustomerGetEndpointV1(pksCustomerCode: string, sInfrastructureproductCode?: 'appcluster01' | 'ezsignuser', options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GlobalCustomerGetEndpointV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
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
         * @param {string} pksCustomerCode The customer code assigned to your account
         * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        globalCustomerGetEndpointV1(pksCustomerCode: string, sInfrastructureproductCode?: 'appcluster01' | 'ezsignuser', options?: any): AxiosPromise<GlobalCustomerGetEndpointV1Response> {
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
     * @param {string} pksCustomerCode The customer code assigned to your account
     * @param {'appcluster01' | 'ezsignuser'} [sInfrastructureproductCode] The infrastructure product Code  If undefined, \&quot;appcluster01\&quot; is assumed
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof GlobalCustomerApi
     */
    public globalCustomerGetEndpointV1(pksCustomerCode: string, sInfrastructureproductCode?: 'appcluster01' | 'ezsignuser', options?: any) {
        return GlobalCustomerApiFp(this.configuration).globalCustomerGetEndpointV1(pksCustomerCode, sInfrastructureproductCode, options).then((request) => request(this.axios, this.basePath));
    }
}
