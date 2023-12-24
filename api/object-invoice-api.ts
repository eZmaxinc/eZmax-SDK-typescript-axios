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
import { InvoiceGetAttachmentsV1Response } from '../model';
// @ts-ignore
import { InvoiceGetCommunicationListV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectInvoiceApi - axios parameter creator
 * @export
 */
export const ObjectInvoiceApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Retrieve Invoice\'s Attachments
         * @param {number} pkiInvoiceID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        invoiceGetAttachmentsV1: async (pkiInvoiceID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiInvoiceID' is not null or undefined
            assertParamExists('invoiceGetAttachmentsV1', 'pkiInvoiceID', pkiInvoiceID)
            const localVarPath = `/1/object/invoice/{pkiInvoiceID}/getAttachments`
                .replace(`{${"pkiInvoiceID"}}`, encodeURIComponent(String(pkiInvoiceID)));
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
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiInvoiceID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        invoiceGetCommunicationListV1: async (pkiInvoiceID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiInvoiceID' is not null or undefined
            assertParamExists('invoiceGetCommunicationListV1', 'pkiInvoiceID', pkiInvoiceID)
            const localVarPath = `/1/object/invoice/{pkiInvoiceID}/getCommunicationList`
                .replace(`{${"pkiInvoiceID"}}`, encodeURIComponent(String(pkiInvoiceID)));
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
 * ObjectInvoiceApi - functional programming interface
 * @export
 */
export const ObjectInvoiceApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectInvoiceApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Retrieve Invoice\'s Attachments
         * @param {number} pkiInvoiceID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async invoiceGetAttachmentsV1(pkiInvoiceID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<InvoiceGetAttachmentsV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.invoiceGetAttachmentsV1(pkiInvoiceID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiInvoiceID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async invoiceGetCommunicationListV1(pkiInvoiceID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<InvoiceGetCommunicationListV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.invoiceGetCommunicationListV1(pkiInvoiceID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectInvoiceApi - factory interface
 * @export
 */
export const ObjectInvoiceApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectInvoiceApiFp(configuration)
    return {
        /**
         * 
         * @summary Retrieve Invoice\'s Attachments
         * @param {number} pkiInvoiceID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        invoiceGetAttachmentsV1(pkiInvoiceID: number, options?: any): AxiosPromise<InvoiceGetAttachmentsV1Response> {
            return localVarFp.invoiceGetAttachmentsV1(pkiInvoiceID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve Communication list
         * @param {number} pkiInvoiceID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        invoiceGetCommunicationListV1(pkiInvoiceID: number, options?: any): AxiosPromise<InvoiceGetCommunicationListV1Response> {
            return localVarFp.invoiceGetCommunicationListV1(pkiInvoiceID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectInvoiceApi - object-oriented interface
 * @export
 * @class ObjectInvoiceApi
 * @extends {BaseAPI}
 */
export class ObjectInvoiceApi extends BaseAPI {
    /**
     * 
     * @summary Retrieve Invoice\'s Attachments
     * @param {number} pkiInvoiceID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectInvoiceApi
     */
    public invoiceGetAttachmentsV1(pkiInvoiceID: number, options?: AxiosRequestConfig) {
        return ObjectInvoiceApiFp(this.configuration).invoiceGetAttachmentsV1(pkiInvoiceID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve Communication list
     * @param {number} pkiInvoiceID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectInvoiceApi
     */
    public invoiceGetCommunicationListV1(pkiInvoiceID: number, options?: AxiosRequestConfig) {
        return ObjectInvoiceApiFp(this.configuration).invoiceGetCommunicationListV1(pkiInvoiceID, options).then((request) => request(this.axios, this.basePath));
    }
}

