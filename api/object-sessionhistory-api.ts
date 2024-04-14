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
import { CommonResponseError } from '../model';
// @ts-ignore
import { HeaderAcceptLanguage } from '../model';
// @ts-ignore
import { SessionhistoryGetListV1Response } from '../model';
// @ts-ignore
import { RequestSignature, IHeadersData } from '../api/request-signature';
/**
 * ObjectSessionhistoryApi - axios parameter creator
 * @export
 */
export const ObjectSessionhistoryApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Retrieve Sessionhistory list
         * @param {SessionhistoryGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        sessionhistoryGetListV1: async (eOrderBy?: SessionhistoryGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options: RawAxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/1/object/sessionhistory/getList`;
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

            if (eOrderBy !== undefined) {
                localVarQueryParameter['eOrderBy'] = eOrderBy;
            }

            if (iRowMax !== undefined) {
                localVarQueryParameter['iRowMax'] = iRowMax;
            }

            if (iRowOffset !== undefined) {
                localVarQueryParameter['iRowOffset'] = iRowOffset;
            }

            if (sFilter !== undefined) {
                localVarQueryParameter['sFilter'] = sFilter;
            }

            if (acceptLanguage != null) {
                localVarHeaderParameter['Accept-Language'] = typeof acceptLanguage === 'string'
                    ? acceptLanguage
                    : JSON.stringify(acceptLanguage);
            }


    
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
 * ObjectSessionhistoryApi - functional programming interface
 * @export
 */
export const ObjectSessionhistoryApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ObjectSessionhistoryApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Retrieve Sessionhistory list
         * @param {SessionhistoryGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async sessionhistoryGetListV1(eOrderBy?: SessionhistoryGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<SessionhistoryGetListV1Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.sessionhistoryGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options);
            const localVarOperationServerIndex = configuration?.serverIndex ?? 0;
            const localVarOperationServerBasePath = operationServerMap['ObjectSessionhistoryApi.sessionhistoryGetListV1']?.[localVarOperationServerIndex]?.url;
            return (axios, basePath) => createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration)(axios, localVarOperationServerBasePath || basePath);
        },
    }
};

/**
 * ObjectSessionhistoryApi - factory interface
 * @export
 */
export const ObjectSessionhistoryApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ObjectSessionhistoryApiFp(configuration)
    return {
        /**
         * 
         * @summary Retrieve Sessionhistory list
         * @param {SessionhistoryGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
         * @param {number} [iRowMax] 
         * @param {number} [iRowOffset] 
         * @param {HeaderAcceptLanguage} [acceptLanguage] 
         * @param {string} [sFilter] 
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        sessionhistoryGetListV1(eOrderBy?: SessionhistoryGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: any): AxiosPromise<SessionhistoryGetListV1Response> {
            return localVarFp.sessionhistoryGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * ObjectSessionhistoryApi - object-oriented interface
 * @export
 * @class ObjectSessionhistoryApi
 * @extends {BaseAPI}
 */
export class ObjectSessionhistoryApi extends BaseAPI {
    /**
     * 
     * @summary Retrieve Sessionhistory list
     * @param {SessionhistoryGetListV1EOrderByEnum} [eOrderBy] Specify how you want the results to be sorted
     * @param {number} [iRowMax] 
     * @param {number} [iRowOffset] 
     * @param {HeaderAcceptLanguage} [acceptLanguage] 
     * @param {string} [sFilter] 
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ObjectSessionhistoryApi
     */
    public sessionhistoryGetListV1(eOrderBy?: SessionhistoryGetListV1EOrderByEnum, iRowMax?: number, iRowOffset?: number, acceptLanguage?: HeaderAcceptLanguage, sFilter?: string, options?: RawAxiosRequestConfig) {
        return ObjectSessionhistoryApiFp(this.configuration).sessionhistoryGetListV1(eOrderBy, iRowMax, iRowOffset, acceptLanguage, sFilter, options).then((request) => request(this.axios, this.basePath));
    }
}

/**
 * @export
 */
export const SessionhistoryGetListV1EOrderByEnum = {
    pkiSessionhistoryID_ASC: 'pkiSessionhistoryID_ASC',
    pkiSessionhistoryID_DESC: 'pkiSessionhistoryID_DESC',
    fkiComputerID_ASC: 'fkiComputerID_ASC',
    fkiComputerID_DESC: 'fkiComputerID_DESC',
    fkiUserID_ASC: 'fkiUserID_ASC',
    fkiUserID_DESC: 'fkiUserID_DESC',
    dtSessionhistoryFirsthit_ASC: 'dtSessionhistoryFirsthit_ASC',
    dtSessionhistoryFirsthit_DESC: 'dtSessionhistoryFirsthit_DESC',
    dtSessionhistoryLasthit_ASC: 'dtSessionhistoryLasthit_ASC',
    dtSessionhistoryLasthit_DESC: 'dtSessionhistoryLasthit_DESC',
    eSessionhistoryEndby_ASC: 'eSessionhistoryEndby_ASC',
    eSessionhistoryEndby_DESC: 'eSessionhistoryEndby_DESC',
    sComputerDescription_ASC: 'sComputerDescription_ASC',
    sComputerDescription_DESC: 'sComputerDescription_DESC',
    sSessionhistoryDuration_ASC: 'sSessionhistoryDuration_ASC',
    sSessionhistoryDuration_DESC: 'sSessionhistoryDuration_DESC',
    sSessionhistoryIP_ASC: 'sSessionhistoryIP_ASC',
    sSessionhistoryIP_DESC: 'sSessionhistoryIP_DESC',
    sUserLoginname_ASC: 'sUserLoginname_ASC',
    sUserLoginname_DESC: 'sUserLoginname_DESC'
} as const;
export type SessionhistoryGetListV1EOrderByEnum = typeof SessionhistoryGetListV1EOrderByEnum[keyof typeof SessionhistoryGetListV1EOrderByEnum];
