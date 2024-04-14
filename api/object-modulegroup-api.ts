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
import { ModulegroupGetAllV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectModulegroupApi - axios parameter creator
 * @export
 */
export const ObjectModulegroupApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Retrieve all Modulegroups
         * @param {ModulegroupGetAllV1EContextEnum} eContext The context of the Modulegroup
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        modulegroupGetAllV1: async (eContext: ModulegroupGetAllV1EContextEnum, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'eContext' is not null or undefined
            assertParamExists('modulegroupGetAllV1', 'eContext', eContext)
            const localVarPath = `/1/object/modulegroup/getAll/{eContext}`
                .replace(`{${"eContext"}}`, encodeURIComponent(String(eContext)));
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

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
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
 * ObjectModulegroupApi - functional programming interface
 * @export
 */
export const ObjectModulegroupApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectModulegroupApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Retrieve all Modulegroups
         * @param {ModulegroupGetAllV1EContextEnum} eContext The context of the Modulegroup
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async modulegroupGetAllV1(eContext: ModulegroupGetAllV1EContextEnum, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ModulegroupGetAllV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.modulegroupGetAllV1(eContext, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectModulegroupApi.modulegroupGetAllV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectModulegroupApi - factory interface
 * @export
 */
export const ObjectModulegroupApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectModulegroupApiFp(configuration)
    return {
        /**
         * 
         * @summary Retrieve all Modulegroups
         * @param {ModulegroupGetAllV1EContextEnum} eContext The context of the Modulegroup
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        modulegroupGetAllV1(eContext: ModulegroupGetAllV1EContextEnum, options?: any): AxiosPromise<ModulegroupGetAllV1Response> {
            return localVarFp.modulegroupGetAllV1(eContext, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectModulegroupApi - object-oriented interface
 * @export
 * @class ObjectModulegroupApi
 * @extends {BaseAPI}
 */
export class ObjectModulegroupApi extends BaseAPI {
    /**
     * 
     * @summary Retrieve all Modulegroups
     * @param {ModulegroupGetAllV1EContextEnum} eContext The context of the Modulegroup
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectModulegroupApi
     */
    public modulegroupGetAllV1(eContext: ModulegroupGetAllV1EContextEnum, options?: RawAxiosRequestConfig) {
        return ObjectModulegroupApiFp(this.configuration).modulegroupGetAllV1(eContext, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const ModulegroupGetAllV1EContextEnum = {
    Api: 'Api',
    User: 'User'
} as const;
export type ModulegroupGetAllV1EContextEnum = typeof ModulegroupGetAllV1EContextEnum[keyof typeof ModulegroupGetAllV1EContextEnum];
