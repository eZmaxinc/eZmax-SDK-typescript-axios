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
import type { EzsignannotationGetObjectV2ResponseMPayload } from './ezsignannotation-get-object-v2-response-mpayload';

/**
 * @type EzsignannotationGetObjectV2Response
 * Response for GET /2/object/ezsignannotation/{pkiEzsignannotationID}
 * @export
 */
/*export type EzsignannotationGetObjectV2Response = CommonResponse;*/
export interface EzsignannotationGetObjectV2Response {
    /**
     * 
     * @type {EzsignannotationGetObjectV2ResponseMPayload}
     * @memberof EzsignannotationGetObjectV2Response
     */
    mPayload:EzsignannotationGetObjectV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignannotationGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignannotationGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignannotationGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignannotationGetObjectV2Response
 */
export class DataObjectEzsignannotationGetObjectV2Response {
    mPayload:EzsignannotationGetObjectV2ResponseMPayload = new DataObjectEzsignannotationGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignannotationGetObjectV2Response Validation Object
 * @class ValidationObjectEzsignannotationGetObjectV2Response
 */
export class ValidationObjectEzsignannotationGetObjectV2Response {
   mPayload = new ValidationObjectEzsignannotationGetObjectV2ResponseMPayload()
} 


