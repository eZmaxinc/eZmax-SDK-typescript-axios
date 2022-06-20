/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
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
import { UserCreateEzsignuserV1Request } from '../model';
// @ts-ignore
import { UserCreateEzsignuserV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ModuleUserApi - axios parameter creator
 * @export
 */
export const ModuleUserApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * The endpoint allows to initiate the creation or a user of type Ezsignuser.  The user will be created only once the email verification process will be completed
         * @summary Create a new User of type Ezsignuser
         * @param {Array<UserCreateEzsignuserV1Request>} userCreateEzsignuserV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userCreateEzsignuserV1: async (userCreateEzsignuserV1Request: Array<UserCreateEzsignuserV1Request>, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'userCreateEzsignuserV1Request' is not null or undefined
            assertParamExists('userCreateEzsignuserV1', 'userCreateEzsignuserV1Request', userCreateEzsignuserV1Request)
            const localVarPath = `/1/module/user/createezsignuser`;
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
            localVarRequestOptions.data = serializeDataIfNeeded(userCreateEzsignuserV1Request, localVarRequestOptions, configuration)

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
    }
};

/**
 * ModuleUserApi - functional programming interface
 * @export
 */
export const ModuleUserApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ModuleUserApiAxiosParamCreator(configuration)
    return {
        /**
         * The endpoint allows to initiate the creation or a user of type Ezsignuser.  The user will be created only once the email verification process will be completed
         * @summary Create a new User of type Ezsignuser
         * @param {Array<UserCreateEzsignuserV1Request>} userCreateEzsignuserV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async userCreateEzsignuserV1(userCreateEzsignuserV1Request: Array<UserCreateEzsignuserV1Request>, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<UserCreateEzsignuserV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.userCreateEzsignuserV1(userCreateEzsignuserV1Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ModuleUserApi - factory interface
 * @export
 */
export const ModuleUserApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ModuleUserApiFp(configuration)
    return {
        /**
         * The endpoint allows to initiate the creation or a user of type Ezsignuser.  The user will be created only once the email verification process will be completed
         * @summary Create a new User of type Ezsignuser
         * @param {Array<UserCreateEzsignuserV1Request>} userCreateEzsignuserV1Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        userCreateEzsignuserV1(userCreateEzsignuserV1Request: Array<UserCreateEzsignuserV1Request>, options?: any): AxiosPromise<UserCreateEzsignuserV1Response> {
            return localVarFp.userCreateEzsignuserV1(userCreateEzsignuserV1Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ModuleUserApi - object-oriented interface
 * @export
 * @class ModuleUserApi
 * @extends {BaseAPI}
 */
export class ModuleUserApi extends BaseAPI {
    /**
     * The endpoint allows to initiate the creation or a user of type Ezsignuser.  The user will be created only once the email verification process will be completed
     * @summary Create a new User of type Ezsignuser
     * @param {Array<UserCreateEzsignuserV1Request>} userCreateEzsignuserV1Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ModuleUserApi
     */
    public userCreateEzsignuserV1(userCreateEzsignuserV1Request: Array<UserCreateEzsignuserV1Request>, options?: AxiosRequestConfig) {
        return ModuleUserApiFp(this.configuration).userCreateEzsignuserV1(userCreateEzsignuserV1Request, options).then((request) => request(this.axios, this.basePath));
    }
}
