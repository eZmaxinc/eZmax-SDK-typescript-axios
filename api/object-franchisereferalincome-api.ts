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
import { FranchisereferalincomeCreateObjectV1Request } from '../model';
// @ts-ignore
import { FranchisereferalincomeCreateObjectV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectFranchisereferalincomeApi - axios parameter creator
 * @export
 */
export const ObjectFranchisereferalincomeApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Franchisereferalincome
         * @param {Array<FranchisereferalincomeCreateObjectV1Request>} franchisereferalincomeCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        franchisereferalincomeCreateObjectV1: async (franchisereferalincomeCreateObjectV1Request: Array<FranchisereferalincomeCreateObjectV1Request>, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'franchisereferalincomeCreateObjectV1Request' is not null or undefined
            assertParamExists('franchisereferalincomeCreateObjectV1', 'franchisereferalincomeCreateObjectV1Request', franchisereferalincomeCreateObjectV1Request)
            const localVarPath = `/1/object/franchisereferalincome`;
            
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
            localVarRequestOptions.data = serializeDataIfNeeded(franchisereferalincomeCreateObjectV1Request, localVarRequestOptions, configuration)

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
    }
};

/**
 * ObjectFranchisereferalincomeApi - functional programming interface
 * @export
 */
export const ObjectFranchisereferalincomeApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectFranchisereferalincomeApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Franchisereferalincome
         * @param {Array<FranchisereferalincomeCreateObjectV1Request>} franchisereferalincomeCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request: Array<FranchisereferalincomeCreateObjectV1Request>, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<FranchisereferalincomeCreateObjectV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ObjectFranchisereferalincomeApi - factory interface
 * @export
 */
export const ObjectFranchisereferalincomeApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectFranchisereferalincomeApiFp(configuration)
    return {
        /**
         * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
         * @summary Create a new Franchisereferalincome
         * @param {Array<FranchisereferalincomeCreateObjectV1Request>} franchisereferalincomeCreateObjectV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request: Array<FranchisereferalincomeCreateObjectV1Request>, options?: any): AxiosPromise<FranchisereferalincomeCreateObjectV1Response> {
            return localVarFp.franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectFranchisereferalincomeApi - object-oriented interface
 * @export
 * @class ObjectFranchisereferalincomeApi
 * @extends {BaseAPI}
 */
export class ObjectFranchisereferalincomeApi extends BaseAPI {
    /**
     * The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.
     * @summary Create a new Franchisereferalincome
     * @param {Array<FranchisereferalincomeCreateObjectV1Request>} franchisereferalincomeCreateObjectV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectFranchisereferalincomeApi
     */
    public franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request: Array<FranchisereferalincomeCreateObjectV1Request>, options?: any) {
        return ObjectFranchisereferalincomeApiFp(this.configuration).franchisereferalincomeCreateObjectV1(franchisereferalincomeCreateObjectV1Request, options).then((request) => request(this.axios, this.basePath));
    }
}
