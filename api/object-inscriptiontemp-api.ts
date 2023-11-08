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
import { InscriptiontempGetCommunicationListV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectInscriptiontempApi - axios parameter creator
 * @export
 */
export const ObjectInscriptiontempApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiInscriptiontempID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        inscriptiontempGetCommunicationListV1: async (pkiInscriptiontempID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiInscriptiontempID' is not null or undefined
            assertParamExists('inscriptiontempGetCommunicationListV1', 'pkiInscriptiontempID', pkiInscriptiontempID)
            const localVarPath = `/1/object/inscriptiontemp/{pkiInscriptiontempID}/getCommunicationList`
                .replace(`{${"pkiInscriptiontempID"}}`, encodeURIComponent(String(pkiInscriptiontempID)));
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
 * ObjectInscriptiontempApi - functional programming interface
 * @export
 */
export const ObjectInscriptiontempApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectInscriptiontempApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiInscriptiontempID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async inscriptiontempGetCommunicationListV1(pkiInscriptiontempID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<InscriptiontempGetCommunicationListV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.inscriptiontempGetCommunicationListV1(pkiInscriptiontempID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectInscriptiontempApi - factory interface
 * @export
 */
export const ObjectInscriptiontempApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectInscriptiontempApiFp(configuration)
    return {
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiInscriptiontempID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        inscriptiontempGetCommunicationListV1(pkiInscriptiontempID: number, options?: any): AxiosPromise<InscriptiontempGetCommunicationListV1Response> {
            return localVarFp.inscriptiontempGetCommunicationListV1(pkiInscriptiontempID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectInscriptiontempApi - object-oriented interface
 * @export
 * @class ObjectInscriptiontempApi
 * @extends {BaseAPI}
 */
export class ObjectInscriptiontempApi extends BaseAPI {
    /**
     * 
     * @summary Retrieve Communication list
     * @param {number} pkiInscriptiontempID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectInscriptiontempApi
     */
    public inscriptiontempGetCommunicationListV1(pkiInscriptiontempID: number, options?: AxiosRequestConfig) {
        return ObjectInscriptiontempApiFp(this.configuration).inscriptiontempGetCommunicationListV1(pkiInscriptiontempID, options).then((request) => request(this.axios, this.basePath));
    }
}

