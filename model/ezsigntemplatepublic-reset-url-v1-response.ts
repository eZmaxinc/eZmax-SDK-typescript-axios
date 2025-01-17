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
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepublicResetUrlV1ResponseMPayload } from './ezsigntemplatepublic-reset-url-v1-response-mpayload';

/**
 * @type EzsigntemplatepublicResetUrlV1Response
 * Response for POST /1/object/ezsigntemplatepublic/{pkiEzsigntemplatepublicID}/resetUrl
 * @export
 */
/*export type EzsigntemplatepublicResetUrlV1Response = CommonResponse;*/
export interface EzsigntemplatepublicResetUrlV1Response {
    /**
     * 
     * @type {EzsigntemplatepublicResetUrlV1ResponseMPayload}
     * @memberof EzsigntemplatepublicResetUrlV1Response
     */
    mPayload:EzsigntemplatepublicResetUrlV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepublicResetUrlV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepublicResetUrlV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepublicResetUrlV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicResetUrlV1Response
 */
export class DataObjectEzsigntemplatepublicResetUrlV1Response {
    mPayload:EzsigntemplatepublicResetUrlV1ResponseMPayload = new DataObjectEzsigntemplatepublicResetUrlV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepublicResetUrlV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepublicResetUrlV1Response
 */
export class ValidationObjectEzsigntemplatepublicResetUrlV1Response {
   mPayload = new ValidationObjectEzsigntemplatepublicResetUrlV1ResponseMPayload()
} 


