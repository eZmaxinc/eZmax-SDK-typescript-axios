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
import type { AttachmentGetAttachmentlogsV1Response } from '../model';
// @ts-ignore
import type { CommonResponseError } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectAttachmentApi - axios parameter creator
 * @export
 */
export const ObjectAttachmentApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * Using this endpoint, you can retrieve the content of an attachment.
         * @summary Retrieve the content
         * @param {number} pkiAttachmentID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        attachmentDownloadV1: async (pkiAttachmentID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiAttachmentID' is not null or undefined
            assertParamExists('attachmentDownloadV1', 'pkiAttachmentID', pkiAttachmentID)
            const localVarPath = `/1/object/attachment/{pkiAttachmentID}/download`
                .replace(`{${"pkiAttachmentID"}}`, encodeURIComponent(String(pkiAttachmentID)));
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

            // authentication Presigned required
            // await setApiKeyToObject(localVarQueryParameter, "sAuthorization", configuration)


    
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
        /**
         * Using this endpoint, you can retrieve the Attachmentlogs of an attachment.
         * @summary Retrieve the Attachmentlogs
         * @param {number} pkiAttachmentID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        attachmentGetAttachmentlogsV1: async (pkiAttachmentID: number, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiAttachmentID' is not null or undefined
            assertParamExists('attachmentGetAttachmentlogsV1', 'pkiAttachmentID', pkiAttachmentID)
            const localVarPath = `/1/object/attachment/{pkiAttachmentID}/getAttachmentlogs`
                .replace(`{${"pkiAttachmentID"}}`, encodeURIComponent(String(pkiAttachmentID)));
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
 * ObjectAttachmentApi - functional programming interface
 * @export
 */
export const ObjectAttachmentApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectAttachmentApiAxiosParamCreator(configuration)
    return {
        /**
         * Using this endpoint, you can retrieve the content of an attachment.
         * @summary Retrieve the content
         * @param {number} pkiAttachmentID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async attachmentDownloadV1(pkiAttachmentID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.attachmentDownloadV1(pkiAttachmentID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectAttachmentApi.attachmentDownloadV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
        /**
         * Using this endpoint, you can retrieve the Attachmentlogs of an attachment.
         * @summary Retrieve the Attachmentlogs
         * @param {number} pkiAttachmentID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async attachmentGetAttachmentlogsV1(pkiAttachmentID: number, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AttachmentGetAttachmentlogsV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.attachmentGetAttachmentlogsV1(pkiAttachmentID, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectAttachmentApi.attachmentGetAttachmentlogsV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectAttachmentApi - factory interface
 * @export
 */
export const ObjectAttachmentApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectAttachmentApiFp(configuration)
    return {
        /**
         * Using this endpoint, you can retrieve the content of an attachment.
         * @summary Retrieve the content
         * @param {number} pkiAttachmentID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        attachmentDownloadV1(pkiAttachmentID: number, options?: RawAxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.attachmentDownloadV1(pkiAttachmentID, options).then((request) => request(axios, basePath));
        },
        /**
         * Using this endpoint, you can retrieve the Attachmentlogs of an attachment.
         * @summary Retrieve the Attachmentlogs
         * @param {number} pkiAttachmentID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        attachmentGetAttachmentlogsV1(pkiAttachmentID: number, options?: RawAxiosRequestConfig): AxiosPromise<AttachmentGetAttachmentlogsV1Response> {
            return localVarFp.attachmentGetAttachmentlogsV1(pkiAttachmentID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectAttachmentApi - object-oriented interface
 * @export
 * @class ObjectAttachmentApi
 * @extends {BaseAPI}
 */
export class ObjectAttachmentApi extends BaseAPI {
    /**
     * Using this endpoint, you can retrieve the content of an attachment.
     * @summary Retrieve the content
     * @param {number} pkiAttachmentID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectAttachmentApi
     */
    public attachmentDownloadV1(pkiAttachmentID: number, options?: RawAxiosRequestConfig) {
        return ObjectAttachmentApiFp(this.configuration).attachmentDownloadV1(pkiAttachmentID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * Using this endpoint, you can retrieve the Attachmentlogs of an attachment.
     * @summary Retrieve the Attachmentlogs
     * @param {number} pkiAttachmentID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectAttachmentApi
     */
    public attachmentGetAttachmentlogsV1(pkiAttachmentID: number, options?: RawAxiosRequestConfig) {
        return ObjectAttachmentApiFp(this.configuration).attachmentGetAttachmentlogsV1(pkiAttachmentID, options).then((request) => request(this.axios, this.basePath));
    }
}

