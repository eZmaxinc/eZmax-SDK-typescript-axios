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
import type { EzsignuserGetObjectV2ResponseMPayload } from './ezsignuser-get-object-v2-response-mpayload';

/**
 * @type EzsignuserGetObjectV2Response
 * Response for GET /2/object/ezsignuser/{pkiEzsignuserID}
 * @export
 */
/*export type EzsignuserGetObjectV2Response = CommonResponse;*/
export interface EzsignuserGetObjectV2Response {
    /**
     * 
     * @type {EzsignuserGetObjectV2ResponseMPayload}
     * @memberof EzsignuserGetObjectV2Response
     */
    mPayload:EzsignuserGetObjectV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignuserGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignuserGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignuserGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignuserGetObjectV2Response
 */
export class DataObjectEzsignuserGetObjectV2Response {
    mPayload:EzsignuserGetObjectV2ResponseMPayload = new DataObjectEzsignuserGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignuserGetObjectV2Response Validation Object
 * @class ValidationObjectEzsignuserGetObjectV2Response
 */
export class ValidationObjectEzsignuserGetObjectV2Response {
   mPayload = new ValidationObjectEzsignuserGetObjectV2ResponseMPayload()
} 


