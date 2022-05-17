/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import globalAxios, { AxiosPromise, AxiosInstance, AxiosRequestConfig } from 'axios';
import { Configuration } from '../configuration';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setOAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationCreateObjectV1Request } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationCreateObjectV1Response } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationCreateObjectV2Request } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationCreateObjectV2Response } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationDeleteObjectV1Response } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationEditObjectV1Request } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationEditObjectV1Response } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationGetInPersonLoginUrlV1Response } from '../model';
// @ts-ignore
import { EzsignfoldersignerassociationGetObjectV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectEzsignfoldersignerassociationApi - axios parameter creator
 * @export
 */
export const ObjectEzsignfoldersignerassociationApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationCreateObjectV1: async (ezsignfoldersignerassociationCreateObjectV1Request: Array<EzsignfoldersignerassociationCreateObjectV1Request>, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsignfoldersignerassociationCreateObjectV1Request' is not null or undefined
            assertParamExists('ezsignfoldersignerassociationCreateObjectV1', 'ezsignfoldersignerassociationCreateObjectV1Request', ezsignfoldersignerassociationCreateObjectV1Request)
            const localVarPath = `/1/object/ezsignfoldersignerassociation`;
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

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignfoldersignerassociationCreateObjectV1Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
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
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {EzsignfoldersignerassociationCreateObjectV2Request} ezsignfoldersignerassociationCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationCreateObjectV2: async (ezsignfoldersignerassociationCreateObjectV2Request: EzsignfoldersignerassociationCreateObjectV2Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'ezsignfoldersignerassociationCreateObjectV2Request' is not null or undefined
            assertParamExists('ezsignfoldersignerassociationCreateObjectV2', 'ezsignfoldersignerassociationCreateObjectV2Request', ezsignfoldersignerassociationCreateObjectV2Request)
            const localVarPath = `/2/object/ezsignfoldersignerassociation`;
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

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignfoldersignerassociationCreateObjectV2Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
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
         * @summary Delete an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationDeleteObjectV1: async (pkiEzsignfoldersignerassociationID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            assertParamExists('ezsignfoldersignerassociationDeleteObjectV1', 'pkiEzsignfoldersignerassociationID', pkiEzsignfoldersignerassociationID)
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
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
                        method: 'DELETE' as string,
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
         * @summary Edit an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {EzsignfoldersignerassociationEditObjectV1Request} ezsignfoldersignerassociationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationEditObjectV1: async (pkiEzsignfoldersignerassociationID: number, ezsignfoldersignerassociationEditObjectV1Request: EzsignfoldersignerassociationEditObjectV1Request, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            assertParamExists('ezsignfoldersignerassociationEditObjectV1', 'pkiEzsignfoldersignerassociationID', pkiEzsignfoldersignerassociationID)
            // verify required parameter 'ezsignfoldersignerassociationEditObjectV1Request' is not null or undefined
            assertParamExists('ezsignfoldersignerassociationEditObjectV1', 'ezsignfoldersignerassociationEditObjectV1Request', ezsignfoldersignerassociationEditObjectV1Request)
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            let basePath = DUMMY_BASE_URL
            if (configuration && configuration.basePath) basePath = configuration.basePath
            const localVarUrlObj = new URL(localVarPath, basePath);

            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions = { method: 'PUT', ...baseOptions, ...options};
            const localVarHeaderParameter = {} as any;
            const localVarQueryParameter = {} as any;

            // authentication Authorization required
            await setApiKeyToObject(localVarHeaderParameter, "Authorization", configuration)


    
            localVarHeaderParameter['Content-Type'] = 'application/json';

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...headersFromBaseOptions, ...localVarHeaderParameter,  ...options.headers};
            localVarRequestOptions.data = serializeDataIfNeeded(ezsignfoldersignerassociationEditObjectV1Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'PUT' as string,
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
         * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
         * @summary Retrieve a Login Url to allow In-Person signing
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetInPersonLoginUrlV1: async (pkiEzsignfoldersignerassociationID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            assertParamExists('ezsignfoldersignerassociationGetInPersonLoginUrlV1', 'pkiEzsignfoldersignerassociationID', pkiEzsignfoldersignerassociationID)
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}/getInPersonLoginUrl`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
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
         * @summary Retrieve an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetObjectV1: async (pkiEzsignfoldersignerassociationID: number, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pkiEzsignfoldersignerassociationID' is not null or undefined
            assertParamExists('ezsignfoldersignerassociationGetObjectV1', 'pkiEzsignfoldersignerassociationID', pkiEzsignfoldersignerassociationID)
            const localVarPath = `/1/object/ezsignfoldersignerassociation/{pkiEzsignfoldersignerassociationID}`
                .replace(`{${"pkiEzsignfoldersignerassociationID"}}`, encodeURIComponent(String(pkiEzsignfoldersignerassociationID)));
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
 * ObjectEzsignfoldersignerassociationApi - functional programming interface
 * @export
 */
export const ObjectEzsignfoldersignerassociationApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectEzsignfoldersignerassociationApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        async ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request: Array<EzsignfoldersignerassociationCreateObjectV1Request>, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfoldersignerassociationCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {EzsignfoldersignerassociationCreateObjectV2Request} ezsignfoldersignerassociationCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldersignerassociationCreateObjectV2(ezsignfoldersignerassociationCreateObjectV2Request: EzsignfoldersignerassociationCreateObjectV2Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfoldersignerassociationCreateObjectV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignfoldersignerassociationCreateObjectV2(ezsignfoldersignerassociationCreateObjectV2Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfoldersignerassociationDeleteObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Edit an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {EzsignfoldersignerassociationEditObjectV1Request} ezsignfoldersignerassociationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldersignerassociationEditObjectV1(pkiEzsignfoldersignerassociationID: number, ezsignfoldersignerassociationEditObjectV1Request: EzsignfoldersignerassociationEditObjectV1Request, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfoldersignerassociationEditObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignfoldersignerassociationEditObjectV1(pkiEzsignfoldersignerassociationID, ezsignfoldersignerassociationEditObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
         * @summary Retrieve a Login Url to allow In-Person signing
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfoldersignerassociationGetInPersonLoginUrlV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID: number, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<EzsignfoldersignerassociationGetObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectEzsignfoldersignerassociationApi - factory interface
 * @export
 */
export const ObjectEzsignfoldersignerassociationApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectEzsignfoldersignerassociationApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @deprecated
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request: Array<EzsignfoldersignerassociationCreateObjectV1Request>, options?: any): AxiosPromise<EzsignfoldersignerassociationCreateObjectV1Response> {
            return localVarFp.ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * The endpoint allows to create one or many elements at once.
         * @summary Create a new Ezsignfoldersignerassociation
         * @param {EzsignfoldersignerassociationCreateObjectV2Request} ezsignfoldersignerassociationCreateObjectV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationCreateObjectV2(ezsignfoldersignerassociationCreateObjectV2Request: EzsignfoldersignerassociationCreateObjectV2Request, options?: any): AxiosPromise<EzsignfoldersignerassociationCreateObjectV2Response> {
            return localVarFp.ezsignfoldersignerassociationCreateObjectV2(ezsignfoldersignerassociationCreateObjectV2Request, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID: number, options?: any): AxiosPromise<EzsignfoldersignerassociationDeleteObjectV1Response> {
            return localVarFp.ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Edit an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {EzsignfoldersignerassociationEditObjectV1Request} ezsignfoldersignerassociationEditObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationEditObjectV1(pkiEzsignfoldersignerassociationID: number, ezsignfoldersignerassociationEditObjectV1Request: EzsignfoldersignerassociationEditObjectV1Request, options?: any): AxiosPromise<EzsignfoldersignerassociationEditObjectV1Response> {
            return localVarFp.ezsignfoldersignerassociationEditObjectV1(pkiEzsignfoldersignerassociationID, ezsignfoldersignerassociationEditObjectV1Request, options).then((request) => request(axios, basePath));
        },
        /**
         * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
         * @summary Retrieve a Login Url to allow In-Person signing
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID: number, options?: any): AxiosPromise<EzsignfoldersignerassociationGetInPersonLoginUrlV1Response> {
            return localVarFp.ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Retrieve an existing Ezsignfoldersignerassociation
         * @param {number} pkiEzsignfoldersignerassociationID 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID: number, options?: any): AxiosPromise<EzsignfoldersignerassociationGetObjectV1Response> {
            return localVarFp.ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectEzsignfoldersignerassociationApi - object-oriented interface
 * @export
 * @class ObjectEzsignfoldersignerassociationApi
 * @extends {BaseAPI}
 */
export class ObjectEzsignfoldersignerassociationApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
     * @summary Create a new Ezsignfoldersignerassociation
     * @param {Array<EzsignfoldersignerassociationCreateObjectV1Request>} ezsignfoldersignerassociationCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @deprecated
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    public ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request: Array<EzsignfoldersignerassociationCreateObjectV1Request>, options?: AxiosRequestConfig) {
        return ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationCreateObjectV1(ezsignfoldersignerassociationCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * The endpoint allows to create one or many elements at once.
     * @summary Create a new Ezsignfoldersignerassociation
     * @param {EzsignfoldersignerassociationCreateObjectV2Request} ezsignfoldersignerassociationCreateObjectV2Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    public ezsignfoldersignerassociationCreateObjectV2(ezsignfoldersignerassociationCreateObjectV2Request: EzsignfoldersignerassociationCreateObjectV2Request, options?: AxiosRequestConfig) {
        return ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationCreateObjectV2(ezsignfoldersignerassociationCreateObjectV2Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete an existing Ezsignfoldersignerassociation
     * @param {number} pkiEzsignfoldersignerassociationID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    public ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID: number, options?: AxiosRequestConfig) {
        return ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationDeleteObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Edit an existing Ezsignfoldersignerassociation
     * @param {number} pkiEzsignfoldersignerassociationID 
     * @param {EzsignfoldersignerassociationEditObjectV1Request} ezsignfoldersignerassociationEditObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    public ezsignfoldersignerassociationEditObjectV1(pkiEzsignfoldersignerassociationID: number, ezsignfoldersignerassociationEditObjectV1Request: EzsignfoldersignerassociationEditObjectV1Request, options?: AxiosRequestConfig) {
        return ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationEditObjectV1(pkiEzsignfoldersignerassociationID, ezsignfoldersignerassociationEditObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * This endpoint returns a Login Url that can be used in a browser or embedded in an I-Frame to allow in person signing.  The signer Login type must be configured as In-Person.
     * @summary Retrieve a Login Url to allow In-Person signing
     * @param {number} pkiEzsignfoldersignerassociationID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    public ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID: number, options?: AxiosRequestConfig) {
        return ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationGetInPersonLoginUrlV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Retrieve an existing Ezsignfoldersignerassociation
     * @param {number} pkiEzsignfoldersignerassociationID 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectEzsignfoldersignerassociationApi
     */
    public ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID: number, options?: AxiosRequestConfig) {
        return ObjectEzsignfoldersignerassociationApiFp(this.configuration).ezsignfoldersignerassociationGetObjectV1(pkiEzsignfoldersignerassociationID, options).then((request) => request(this.axios, this.basePath));
    }
}
