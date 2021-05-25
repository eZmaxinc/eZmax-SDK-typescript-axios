/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.43
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
import { EzsigndocumentApplyEzsigntemplateV1Request } from '../model';
// @ts-ignore
import { EzsigndocumentApplyEzsigntemplateV1Response } from '../model';
// @ts-ignore
import { EzsigndocumentCreateObjectV1Request } from '../model';
// @ts-ignore
import { EzsigndocumentCreateObjectV1Response } from '../model';
// @ts-ignore
import { EzsigndocumentDeleteObjectV1Response } from '../model';
// @ts-ignore
import { EzsigndocumentGetDownloadUrlV1Response } from '../model';
// @ts-ignore
import { EzsigndocumentGetObjectV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsigndocumentApi - axios parameter creator
 * @export
 */
export const ObjectEzsigndocumentApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * This endpoint applies a predefined template to the ezsign document. This allows to automatically apply all the form and signature fields on a document in a single step.  The document must not already have fields otherwise an error will be returned.
         * @summary Apply an Ezsign Template to the Ezsigndocument.
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {EzsigndocumentApplyEzsigntemplateV1Request} ezsigndocumentApplyEzsigntemplateV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentApplyEzsigntemplateV1: async (pkiEzsigndocumentID: number, ezsigndocumentApplyEzsigntemplateV1Request: EzsigndocumentApplyEzsigntemplateV1Request, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigndocumentID' is not null or undefined
            assertParamExists('ezsigndocumentApplyEzsigntemplateV1', 'pkiEzsigndocumentID', pkiEzsigndocumentID)
            // verify required parameter 'ezsigndocumentApplyEzsigntemplateV1Request' is not null or undefined
            assertParamExists('ezsigndocumentApplyEzsigntemplateV1', 'ezsigndocumentApplyEzsigntemplateV1Request', ezsigndocumentApplyEzsigntemplateV1Request)
            const localVarPath = `/1/object/ezsigndocument/{pkiEzsigndocumentID}/applyezsigntemplate`
                .replace(`{${"pkiEzsigndocumentID"}}`, encodeURIComponent(String(pkiEzsigndocumentID)));
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

            setSearchParams(localVarUrlObj, localVarQueryParameter, options.query);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(ezsigndocumentApplyEzsigntemplateV1Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
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
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsigndocument
         * @param {Array<EzsigndocumentCreateObjectV1Request>} ezsigndocumentCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentCreateObjectV1: async (ezsigndocumentCreateObjectV1Request: Array<EzsigndocumentCreateObjectV1Request>, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsigndocumentCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsigndocumentCreateObjectV1', 'ezsigndocumentCreateObjectV1Request', ezsigndocumentCreateObjectV1Request)
            const localVarPath = `/1/object/ezsigndocument`;
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

            setSearchParams(localVarUrlObj, localVarQueryParameter, options.query);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(ezsigndocumentCreateObjectV1Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
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
        /**
         * 
         * @summary Delete an existing Ezsigndocument
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentDeleteObjectV1: async (pkiEzsigndocumentID: number, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigndocumentID' is not null or undefined
            assertParamExists('ezsigndocumentDeleteObjectV1', 'pkiEzsigndocumentID', pkiEzsigndocumentID)
            const localVarPath = `/1/object/ezsigndocument/{pkiEzsigndocumentID}`
                .replace(`{${"pkiEzsigndocumentID"}}`, encodeURIComponent(String(pkiEzsigndocumentID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            const localVarUrlObj = new URL(localVarPath, basePath);
	    
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'DELETE', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
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
                        method: 'DELETE' as string,
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
        /**
         * 
         * @summary Retrieve an existing Ezsigndocument\'s children IDs
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentGetChildrenV1: async (pkiEzsigndocumentID: number, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigndocumentID' is not null or undefined
            assertParamExists('ezsigndocumentGetChildrenV1', 'pkiEzsigndocumentID', pkiEzsigndocumentID)
            const localVarPath = `/1/object/ezsigndocument/{pkiEzsigndocumentID}/getChildren`
                .replace(`{${"pkiEzsigndocumentID"}}`, encodeURIComponent(String(pkiEzsigndocumentID)));
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
        /**
         * This endpoint returns URLs to different files that can be downloaded during the signing process.  These links will expire after 5 minutes so the download of the file should be made soon after retrieving the link.
         * @summary Retrieve a URL to download documents.
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {'Initial' | 'Signed' | 'Proof' | 'Proofdocument'} eDocumentType The type of document to retrieve.  1. **Initial** Is the initial document before any signature were applied. 2. **Signed** Is the final document once all signatures were applied. 3. **Proofdocument** Is the evidence report. 4. **Proof** Is the complete evidence archive including all of the above and more. 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentGetDownloadUrlV1: async (pkiEzsigndocumentID: number, eDocumentType: 'Initial' | 'Signed' | 'Proof' | 'Proofdocument', options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigndocumentID' is not null or undefined
            assertParamExists('ezsigndocumentGetDownloadUrlV1', 'pkiEzsigndocumentID', pkiEzsigndocumentID)
            // verify required parameter 'eDocumentType' is not null or undefined
            assertParamExists('ezsigndocumentGetDownloadUrlV1', 'eDocumentType', eDocumentType)
            const localVarPath = `/1/object/ezsigndocument/{pkiEzsigndocumentID}/getDownloadUrl/{eDocumentType}`
                .replace(`{${"pkiEzsigndocumentID"}}`, encodeURIComponent(String(pkiEzsigndocumentID)))
                .replace(`{${"eDocumentType"}}`, encodeURIComponent(String(eDocumentType)));
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
        /**
         * 
         * @summary Retrieve an existing Ezsigndocument
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentGetObjectV1: async (pkiEzsigndocumentID: number, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsigndocumentID' is not null or undefined
            assertParamExists('ezsigndocumentGetObjectV1', 'pkiEzsigndocumentID', pkiEzsigndocumentID)
            const localVarPath = `/1/object/ezsigndocument/{pkiEzsigndocumentID}`
                .replace(`{${"pkiEzsigndocumentID"}}`, encodeURIComponent(String(pkiEzsigndocumentID)));
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
 * ObjectEzsigndocumentApi - functional programming interface
 * @export
 */
export const ObjectEzsigndocumentApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsigndocumentApiAxiosParamCreator(configuration)
    return {
        /**
         * This endpoint applies a predefined template to the ezsign document. This allows to automatically apply all the form and signature fields on a document in a single step.  The document must not already have fields otherwise an error will be returned.
         * @summary Apply an Ezsign Template to the Ezsigndocument.
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {EzsigndocumentApplyEzsigntemplateV1Request} ezsigndocumentApplyEzsigntemplateV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigndocumentApplyEzsigntemplateV1(pkiEzsigndocumentID: number, ezsigndocumentApplyEzsigntemplateV1Request: EzsigndocumentApplyEzsigntemplateV1Request, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigndocumentApplyEzsigntemplateV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigndocumentApplyEzsigntemplateV1(pkiEzsigndocumentID, ezsigndocumentApplyEzsigntemplateV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsigndocument
         * @param {Array<EzsigndocumentCreateObjectV1Request>} ezsigndocumentCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigndocumentCreateObjectV1(ezsigndocumentCreateObjectV1Request: Array<EzsigndocumentCreateObjectV1Request>, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigndocumentCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigndocumentCreateObjectV1(ezsigndocumentCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete an existing Ezsigndocument
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigndocumentDeleteObjectV1(pkiEzsigndocumentID: number, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigndocumentDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigndocumentDeleteObjectV1(pkiEzsigndocumentID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigndocument\'s children IDs
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigndocumentGetChildrenV1(pkiEzsigndocumentID: number, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigndocumentGetChildrenV1(pkiEzsigndocumentID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * This endpoint returns URLs to different files that can be downloaded during the signing process.  These links will expire after 5 minutes so the download of the file should be made soon after retrieving the link.
         * @summary Retrieve a URL to download documents.
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {'Initial' | 'Signed' | 'Proof' | 'Proofdocument'} eDocumentType The type of document to retrieve.  1. **Initial** Is the initial document before any signature were applied. 2. **Signed** Is the final document once all signatures were applied. 3. **Proofdocument** Is the evidence report. 4. **Proof** Is the complete evidence archive including all of the above and more. 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigndocumentGetDownloadUrlV1(pkiEzsigndocumentID: number, eDocumentType: 'Initial' | 'Signed' | 'Proof' | 'Proofdocument', options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigndocumentGetDownloadUrlV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigndocumentGetDownloadUrlV1(pkiEzsigndocumentID, eDocumentType, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigndocument
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsigndocumentGetObjectV1(pkiEzsigndocumentID: number, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsigndocumentGetObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsigndocumentGetObjectV1(pkiEzsigndocumentID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectEzsigndocumentApi - factory interface
 * @export
 */
export const ObjectEzsigndocumentApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsigndocumentApiFp(configuration)
    return {
        /**
         * This endpoint applies a predefined template to the ezsign document. This allows to automatically apply all the form and signature fields on a document in a single step.  The document must not already have fields otherwise an error will be returned.
         * @summary Apply an Ezsign Template to the Ezsigndocument.
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {EzsigndocumentApplyEzsigntemplateV1Request} ezsigndocumentApplyEzsigntemplateV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentApplyEzsigntemplateV1(pkiEzsigndocumentID: number, ezsigndocumentApplyEzsigntemplateV1Request: EzsigndocumentApplyEzsigntemplateV1Request, options?: any): AxiosPromise<EzsigndocumentApplyEzsigntemplateV1Response> {
            return localVarFp.ezsigndocumentApplyEzsigntemplateV1(pkiEzsigndocumentID, ezsigndocumentApplyEzsigntemplateV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsigndocument
         * @param {Array<EzsigndocumentCreateObjectV1Request>} ezsigndocumentCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentCreateObjectV1(ezsigndocumentCreateObjectV1Request: Array<EzsigndocumentCreateObjectV1Request>, options?: any): AxiosPromise<EzsigndocumentCreateObjectV1Response> {
            return localVarFp.ezsigndocumentCreateObjectV1(ezsigndocumentCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsigndocument
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentDeleteObjectV1(pkiEzsigndocumentID: number, options?: any): AxiosPromise<EzsigndocumentDeleteObjectV1Response> {
            return localVarFp.ezsigndocumentDeleteObjectV1(pkiEzsigndocumentID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigndocument\'s children IDs
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentGetChildrenV1(pkiEzsigndocumentID: number, options?: any): AxiosPromise<void> {
            return localVarFp.ezsigndocumentGetChildrenV1(pkiEzsigndocumentID, options).then((request) => request(axios, basePath));
        },
        /**
         * This endpoint returns URLs to different files that can be downloaded during the signing process.  These links will expire after 5 minutes so the download of the file should be made soon after retrieving the link.
         * @summary Retrieve a URL to download documents.
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {'Initial' | 'Signed' | 'Proof' | 'Proofdocument'} eDocumentType The type of document to retrieve.  1. **Initial** Is the initial document before any signature were applied. 2. **Signed** Is the final document once all signatures were applied. 3. **Proofdocument** Is the evidence report. 4. **Proof** Is the complete evidence archive including all of the above and more. 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentGetDownloadUrlV1(pkiEzsigndocumentID: number, eDocumentType: 'Initial' | 'Signed' | 'Proof' | 'Proofdocument', options?: any): AxiosPromise<EzsigndocumentGetDownloadUrlV1Response> {
            return localVarFp.ezsigndocumentGetDownloadUrlV1(pkiEzsigndocumentID, eDocumentType, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsigndocument
         * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsigndocumentGetObjectV1(pkiEzsigndocumentID: number, options?: any): AxiosPromise<EzsigndocumentGetObjectV1Response> {
            return localVarFp.ezsigndocumentGetObjectV1(pkiEzsigndocumentID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsigndocumentApi - object-oriented interface
 * @export
 * @class ObjectEzsigndocumentApi
 * @extends {BaseAPI}
 */
export class ObjectEzsigndocumentApi extends BaseAPI {
    /**
     * This endpoint applies a predefined template to the ezsign document. This allows to automatically apply all the form and signature fields on a document in a single step.  The document must not already have fields otherwise an error will be returned.
     * @summary Apply an Ezsign Template to the Ezsigndocument.
     * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
     * @param {EzsigndocumentApplyEzsigntemplateV1Request} ezsigndocumentApplyEzsigntemplateV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigndocumentApi
     */
    public ezsigndocumentApplyEzsigntemplateV1(pkiEzsigndocumentID: number, ezsigndocumentApplyEzsigntemplateV1Request: EzsigndocumentApplyEzsigntemplateV1Request, options?: any) {
        return ObjectEzsigndocumentApiFp(this.configuration).ezsigndocumentApplyEzsigntemplateV1(pkiEzsigndocumentID, ezsigndocumentApplyEzsigntemplateV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
     * @summary Create a new Ezsigndocument
     * @param {Array<EzsigndocumentCreateObjectV1Request>} ezsigndocumentCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigndocumentApi
     */
    public ezsigndocumentCreateObjectV1(ezsigndocumentCreateObjectV1Request: Array<EzsigndocumentCreateObjectV1Request>, options?: any) {
        return ObjectEzsigndocumentApiFp(this.configuration).ezsigndocumentCreateObjectV1(ezsigndocumentCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsigndocument
     * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigndocumentApi
     */
    public ezsigndocumentDeleteObjectV1(pkiEzsigndocumentID: number, options?: any) {
        return ObjectEzsigndocumentApiFp(this.configuration).ezsigndocumentDeleteObjectV1(pkiEzsigndocumentID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsigndocument\'s children IDs
     * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigndocumentApi
     */
    public ezsigndocumentGetChildrenV1(pkiEzsigndocumentID: number, options?: any) {
        return ObjectEzsigndocumentApiFp(this.configuration).ezsigndocumentGetChildrenV1(pkiEzsigndocumentID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * This endpoint returns URLs to different files that can be downloaded during the signing process.  These links will expire after 5 minutes so the download of the file should be made soon after retrieving the link.
     * @summary Retrieve a URL to download documents.
     * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
     * @param {'Initial' | 'Signed' | 'Proof' | 'Proofdocument'} eDocumentType The type of document to retrieve.  1. **Initial** Is the initial document before any signature were applied. 2. **Signed** Is the final document once all signatures were applied. 3. **Proofdocument** Is the evidence report. 4. **Proof** Is the complete evidence archive including all of the above and more. 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigndocumentApi
     */
    public ezsigndocumentGetDownloadUrlV1(pkiEzsigndocumentID: number, eDocumentType: 'Initial' | 'Signed' | 'Proof' | 'Proofdocument', options?: any) {
        return ObjectEzsigndocumentApiFp(this.configuration).ezsigndocumentGetDownloadUrlV1(pkiEzsigndocumentID, eDocumentType, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsigndocument
     * @param {number} pkiEzsigndocumentID The unique ID of the Ezsigndocument
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsigndocumentApi
     */
    public ezsigndocumentGetObjectV1(pkiEzsigndocumentID: number, options?: any) {
        return ObjectEzsigndocumentApiFp(this.configuration).ezsigndocumentGetObjectV1(pkiEzsigndocumentID, options).then((request) => request(this.axios, this.basePath));
    }
}
