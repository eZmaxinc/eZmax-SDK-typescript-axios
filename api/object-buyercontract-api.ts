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
import type { AxiosPromise, AxiosInstance, RawAxiosRequestConfig } from 'axios';
import globalAxios from 'axios';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError, operationServerMap } from '../base';
// @ts-ignore
import { BuyercontractGetCommunicationListV1Response } from '../model';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectBuyercontractApi - axios parameter creator
 * @export
 */
export const ObjectBuyercontractApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiBuyercontractID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        buyercontractGetCommunicationListV1: async (pkiBuyercontractID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiBuyercontractID' is not null or undefined
            assertParamExists('buyercontractGetCommunicationListV1', 'pkiBuyercontractID', pkiBuyercontractID)
            const localVarPath = `/1/object/buyercontract/{pkiBuyercontractID}/getCommunicationList`
                .replace(`{${"pkiBuyercontractID"}}`, encodeURIComponent(String(pkiBuyercontractID)));
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
 * ObjectBuyercontractApi - functional programming interface
 * @export
 */
export const ObjectBuyercontractApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectBuyercontractApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiBuyercontractID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async buyercontractGetCommunicationListV1(pkiBuyercontractID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<BuyercontractGetCommunicationListV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.buyercontractGetCommunicationListV1(pkiBuyercontractID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectBuyercontractApi.buyercontractGetCommunicationListV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectBuyercontractApi - factory interface
 * @export
 */
export const ObjectBuyercontractApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectBuyercontractApiFp(configuration)
    return {
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiBuyercontractID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        buyercontractGetCommunicationListV1(pkiBuyercontractID: number, options?: any): AxiosPromise<BuyercontractGetCommunicationListV1Response> {
            return localVarFp.buyercontractGetCommunicationListV1(pkiBuyercontractID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectBuyercontractApi - object-oriented interface
 * @export
 * @class ObjectBuyercontractApi
 * @extends {BaseAPI}
 */
export class ObjectBuyercontractApi extends BaseAPI {
    /**
     * 
     * @summary Retrieve Communication list
     * @param {number} pkiBuyercontractID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectBuyercontractApi
     */
    public buyercontractGetCommunicationListV1(pkiBuyercontractID: number, options?: RawAxiosRequestConfig) {
        return ObjectBuyercontractApiFp(this.configuration).buyercontractGetCommunicationListV1(pkiBuyercontractID, options).then((request) => request(this.axios, this.basePath));
    }
}

