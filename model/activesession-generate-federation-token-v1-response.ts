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


// May contain unused imports in some cases
// @ts-ignore
import type { ActivesessionGenerateFederationTokenV1ResponseMPayload } from './activesession-generate-federation-token-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

/**
 * @type ActivesessionGenerateFederationTokenV1Response
 * Response for POST /1/object/activesession/generateFederationToken
 * @export
 */
/*export type ActivesessionGenerateFederationTokenV1Response = CommonResponse;*/
export interface ActivesessionGenerateFederationTokenV1Response {
    /**
     * 
     * @type {ActivesessionGenerateFederationTokenV1ResponseMPayload}
     * @memberof ActivesessionGenerateFederationTokenV1Response
     */
    mPayload:ActivesessionGenerateFederationTokenV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectActivesessionGenerateFederationTokenV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectActivesessionGenerateFederationTokenV1ResponseMPayload } from './'

/**
 * @export 
 * A ActivesessionGenerateFederationTokenV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectActivesessionGenerateFederationTokenV1Response
 */
export class DataObjectActivesessionGenerateFederationTokenV1Response {
    mPayload:ActivesessionGenerateFederationTokenV1ResponseMPayload = new DataObjectActivesessionGenerateFederationTokenV1ResponseMPayload()
}

/**
 * @export 
 * A ActivesessionGenerateFederationTokenV1Response Validation Object
 * @class ValidationObjectActivesessionGenerateFederationTokenV1Response
 */
export class ValidationObjectActivesessionGenerateFederationTokenV1Response {
   mPayload = new ValidationObjectActivesessionGenerateFederationTokenV1ResponseMPayload()
} 


