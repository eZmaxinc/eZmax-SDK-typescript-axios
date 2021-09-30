/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.0
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
import { AuthenticateAuthenticateV2Request } from '../model';
// @ts-ignore
import { AuthenticateAuthenticateV2Response } from '../model';
// @ts-ignore
import { CommonResponseError } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ModuleAuthenticateApi - axios parameter creator
 * @export
 */
export const ModuleAuthenticateApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * This endpoint authenticates a user.
         * @summary Authenticate a user
         * @param {'ezsignuser'} eSessionType 
         * @param {AuthenticateAuthenticateV2Request} authenticateAuthenticateV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        authenticateAuthenticateV2: async (eSessionType: 'ezsignuser', authenticateAuthenticateV2Request: AuthenticateAuthenticateV2Request, options: any = {}): Promise<RequestArgs> => {
            // verify required parameter 'eSessionType' is not null or undefined
            assertParamExists('authenticateAuthenticateV2', 'eSessionType', eSessionType)
            // verify required parameter 'authenticateAuthenticateV2Request' is not null or undefined
            assertParamExists('authenticateAuthenticateV2', 'authenticateAuthenticateV2Request', authenticateAuthenticateV2Request)
            const localVarPath = `/2/module/authenticate/authenticate/{eSessionType}`
                .replace(`{${"eSessionType"}}`, encodeURIComponent(String(eSessionType)));
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
            localVarRequestOptions.data = serializeDataIfNeeded(authenticateAuthenticateV2Request, localVarRequestOptions, configuration)

            // Signature
            if (configuration && configuration.apiKey) {
                const secret = configuration.getSecret()
                if (secret) {
                    const headers:IHeadersData = {
                        authorization: configuration.apiKey as string,
                        secret: secret as string,
                        method: 'POST' as string,
                        url: basePath + localVarPath as string,
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
 * ModuleAuthenticateApi - functional programming interface
 * @export
 */
export const ModuleAuthenticateApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ModuleAuthenticateApiAxiosParamCreator(configuration)
    return {
        /**
         * This endpoint authenticates a user.
         * @summary Authenticate a user
         * @param {'ezsignuser'} eSessionType 
         * @param {AuthenticateAuthenticateV2Request} authenticateAuthenticateV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async authenticateAuthenticateV2(eSessionType: 'ezsignuser', authenticateAuthenticateV2Request: AuthenticateAuthenticateV2Request, options?: any): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AuthenticateAuthenticateV2Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.authenticateAuthenticateV2(eSessionType, authenticateAuthenticateV2Request, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ModuleAuthenticateApi - factory interface
 * @export
 */
export const ModuleAuthenticateApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ModuleAuthenticateApiFp(configuration)
    return {
        /**
         * This endpoint authenticates a user.
         * @summary Authenticate a user
         * @param {'ezsignuser'} eSessionType 
         * @param {AuthenticateAuthenticateV2Request} authenticateAuthenticateV2Request 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        authenticateAuthenticateV2(eSessionType: 'ezsignuser', authenticateAuthenticateV2Request: AuthenticateAuthenticateV2Request, options?: any): AxiosPromise<AuthenticateAuthenticateV2Response> {
            return localVarFp.authenticateAuthenticateV2(eSessionType, authenticateAuthenticateV2Request, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ModuleAuthenticateApi - object-oriented interface
 * @export
 * @class ModuleAuthenticateApi
 * @extends {BaseAPI}
 */
export class ModuleAuthenticateApi extends BaseAPI {
    /**
     * This endpoint authenticates a user.
     * @summary Authenticate a user
     * @param {'ezsignuser'} eSessionType 
     * @param {AuthenticateAuthenticateV2Request} authenticateAuthenticateV2Request 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ModuleAuthenticateApi
     */
    public authenticateAuthenticateV2(eSessionType: 'ezsignuser', authenticateAuthenticateV2Request: AuthenticateAuthenticateV2Request, options?: any) {
        return ModuleAuthenticateApiFp(this.configuration).authenticateAuthenticateV2(eSessionType, authenticateAuthenticateV2Request, options).then((request) => request(this.axios, this.basePath));
    }
}
