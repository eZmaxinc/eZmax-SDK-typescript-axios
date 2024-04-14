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
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError, operationServerMap } from '../base';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { FieldPksEzmaxclientOs } from '../model';
// @ts-ignore
import { GlobalEzmaxclientVersionV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * GlobalEzmaxclientApi - axios parameter creator
 * @export
 */
export const GlobalEzmaxclientApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Retrieve the latest version of the Ezmaxclient that is available on the store.
         * @summary Retrieve the latest version of the Ezmaxclient
         * @param {FieldPksEzmaxclientOs} pksEzmaxclientOs 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        globalEzmaxclientVersionV1: async (pksEzmaxclientOs: FieldPksEzmaxclientOs, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pksEzmaxclientOs' is not null or undefined
            assertParamExists('globalEzmaxclientVersionV1', 'pksEzmaxclientOs', pksEzmaxclientOs)
            const localVarPath = `/1/ezmaxclient/{pksEzmaxclientOs}/version`
                .replace(`{${"pksEzmaxclientOs"}}`, encodeURIComponent(String(pksEzmaxclientOs)));
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
 * GlobalEzmaxclientApi - functional programming interface
 * @export
 */
export const GlobalEzmaxclientApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = GlobalEzmaxclientApiAxiosParamCreator(configuration)
    return {
        /**
         * Retrieve the latest version of the Ezmaxclient that is available on the store.
         * @summary Retrieve the latest version of the Ezmaxclient
         * @param {FieldPksEzmaxclientOs} pksEzmaxclientOs 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async globalEzmaxclientVersionV1(pksEzmaxclientOs: FieldPksEzmaxclientOs, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GlobalEzmaxclientVersionV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.globalEzmaxclientVersionV1(pksEzmaxclientOs, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['GlobalEzmaxclientApi.globalEzmaxclientVersionV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * GlobalEzmaxclientApi - factory interface
 * @export
 */
export const GlobalEzmaxclientApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = GlobalEzmaxclientApiFp(configuration)
    return {
        /**
         * Retrieve the latest version of the Ezmaxclient that is available on the store.
         * @summary Retrieve the latest version of the Ezmaxclient
         * @param {FieldPksEzmaxclientOs} pksEzmaxclientOs 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        globalEzmaxclientVersionV1(pksEzmaxclientOs: FieldPksEzmaxclientOs, options?: any): AxiosPromise<GlobalEzmaxclientVersionV1Response> {
            return localVarFp.globalEzmaxclientVersionV1(pksEzmaxclientOs, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * GlobalEzmaxclientApi - object-oriented interface
 * @export
 * @class GlobalEzmaxclientApi
 * @extends {BaseAPI}
 */
export class GlobalEzmaxclientApi extends BaseAPI {
    /**
     * Retrieve the latest version of the Ezmaxclient that is available on the store.
     * @summary Retrieve the latest version of the Ezmaxclient
     * @param {FieldPksEzmaxclientOs} pksEzmaxclientOs 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof GlobalEzmaxclientApi
     */
    public globalEzmaxclientVersionV1(pksEzmaxclientOs: FieldPksEzmaxclientOs, options?: RawAxiosRequestConfig) {
        return GlobalEzmaxclientApiFp(this.configuration).globalEzmaxclientVersionV1(pksEzmaxclientOs, options).then((request) => request(this.axios, this.basePath));
    }
}

