/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
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
import type { EzmaxcasePatchObjectV1Request } from '../model';
// @ts-ignore
import type { EzmaxcasePatchObjectV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzmaxcaseApi - axios parameter creator
 * @export
 */
export const ObjectEzmaxcaseApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Patch an existing Ezmaxcase
         * @param {number} pkiEzmaxcaseID The unique ID of the Ezmaxcase
         * @param {EzmaxcasePatchObjectV1Request} ezmaxcasePatchObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezmaxcasePatchObjectV1: async (pkiEzmaxcaseID: number, ezmaxcasePatchObjectV1Request: EzmaxcasePatchObjectV1Request, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzmaxcaseID' is not null or undefined
            assertParamExists('ezmaxcasePatchObjectV1', 'pkiEzmaxcaseID', pkiEzmaxcaseID)
            // verify required parameter 'ezmaxcasePatchObjectV1Request' is not null or undefined
            assertParamExists('ezmaxcasePatchObjectV1', 'ezmaxcasePatchObjectV1Request', ezmaxcasePatchObjectV1Request)
            const localVarPath = `/1/object/ezmaxcase/{pkiEzmaxcaseID}`
                .replace(`{${"pkiEzmaxcaseID"}}`, encodeURIComponent(String(pkiEzmaxcaseID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            //const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'PATCH', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            //localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(ezmaxcasePatchObjectV1Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'PATCH' as string,
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
 * ObjectEzmaxcaseApi - functional programming interface
 * @export
 */
export const ObjectEzmaxcaseApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzmaxcaseApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Patch an existing Ezmaxcase
         * @param {number} pkiEzmaxcaseID The unique ID of the Ezmaxcase
         * @param {EzmaxcasePatchObjectV1Request} ezmaxcasePatchObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezmaxcasePatchObjectV1(pkiEzmaxcaseID: number, ezmaxcasePatchObjectV1Request: EzmaxcasePatchObjectV1Request, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzmaxcasePatchObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezmaxcasePatchObjectV1(pkiEzmaxcaseID, ezmaxcasePatchObjectV1Request, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectEzmaxcaseApi.ezmaxcasePatchObjectV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectEzmaxcaseApi - factory interface
 * @export
 */
export const ObjectEzmaxcaseApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzmaxcaseApiFp(configuration)
    return {
        /**
         * 
         * @summary Patch an existing Ezmaxcase
         * @param {number} pkiEzmaxcaseID The unique ID of the Ezmaxcase
         * @param {EzmaxcasePatchObjectV1Request} ezmaxcasePatchObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezmaxcasePatchObjectV1(pkiEzmaxcaseID: number, ezmaxcasePatchObjectV1Request: EzmaxcasePatchObjectV1Request, options?: RawAxiosRequestConfig): AxiosPromise<EzmaxcasePatchObjectV1Response> {
            return localVarFp.ezmaxcasePatchObjectV1(pkiEzmaxcaseID, ezmaxcasePatchObjectV1Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzmaxcaseApi - object-oriented interface
 * @export
 * @class ObjectEzmaxcaseApi
 * @extends {BaseAPI}
 */
export class ObjectEzmaxcaseApi extends BaseAPI {
    /**
     * 
     * @summary Patch an existing Ezmaxcase
     * @param {number} pkiEzmaxcaseID The unique ID of the Ezmaxcase
     * @param {EzmaxcasePatchObjectV1Request} ezmaxcasePatchObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzmaxcaseApi
     */
    public ezmaxcasePatchObjectV1(pkiEzmaxcaseID: number, ezmaxcasePatchObjectV1Request: EzmaxcasePatchObjectV1Request, options?: RawAxiosRequestConfig) {
        return ObjectEzmaxcaseApiFp(this.configuration).ezmaxcasePatchObjectV1(pkiEzmaxcaseID, ezmaxcasePatchObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }
}

