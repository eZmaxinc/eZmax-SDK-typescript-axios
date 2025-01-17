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
import type { EzsigntemplatepublicGetObjectV2ResponseMPayload } from './ezsigntemplatepublic-get-object-v2-response-mpayload';

/**
 * @type EzsigntemplatepublicGetObjectV2Response
 * Response for GET /2/object/ezsigntemplatepublic/{pkiEzsigntemplatepublicID}
 * @export
 */
/*export type EzsigntemplatepublicGetObjectV2Response = CommonResponse;*/
export interface EzsigntemplatepublicGetObjectV2Response {
    /**
     * 
     * @type {EzsigntemplatepublicGetObjectV2ResponseMPayload}
     * @memberof EzsigntemplatepublicGetObjectV2Response
     */
    mPayload:EzsigntemplatepublicGetObjectV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepublicGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepublicGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepublicGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicGetObjectV2Response
 */
export class DataObjectEzsigntemplatepublicGetObjectV2Response {
    mPayload:EzsigntemplatepublicGetObjectV2ResponseMPayload = new DataObjectEzsigntemplatepublicGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepublicGetObjectV2Response Validation Object
 * @class ValidationObjectEzsigntemplatepublicGetObjectV2Response
 */
export class ValidationObjectEzsigntemplatepublicGetObjectV2Response {
   mPayload = new ValidationObjectEzsigntemplatepublicGetObjectV2ResponseMPayload()
} 


