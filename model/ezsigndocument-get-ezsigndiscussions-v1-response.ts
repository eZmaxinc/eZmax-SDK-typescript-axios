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
import type { EzsigndocumentGetEzsigndiscussionsV1ResponseMPayload } from './ezsigndocument-get-ezsigndiscussions-v1-response-mpayload';

/**
 * @type EzsigndocumentGetEzsigndiscussionsV1Response
 * Response for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getEzsigndiscussions
 * @export
 */
/*export type EzsigndocumentGetEzsigndiscussionsV1Response = CommonResponse;*/
export interface EzsigndocumentGetEzsigndiscussionsV1Response {
    /**
     * 
     * @type {EzsigndocumentGetEzsigndiscussionsV1ResponseMPayload}
     * @memberof EzsigndocumentGetEzsigndiscussionsV1Response
     */
    mPayload:EzsigndocumentGetEzsigndiscussionsV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentGetEzsigndiscussionsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetEzsigndiscussionsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndocumentGetEzsigndiscussionsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetEzsigndiscussionsV1Response
 */
export class DataObjectEzsigndocumentGetEzsigndiscussionsV1Response {
    mPayload:EzsigndocumentGetEzsigndiscussionsV1ResponseMPayload = new DataObjectEzsigndocumentGetEzsigndiscussionsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigndocumentGetEzsigndiscussionsV1Response Validation Object
 * @class ValidationObjectEzsigndocumentGetEzsigndiscussionsV1Response
 */
export class ValidationObjectEzsigndocumentGetEzsigndiscussionsV1Response {
   mPayload = new ValidationObjectEzsigndocumentGetEzsigndiscussionsV1ResponseMPayload()
} 


