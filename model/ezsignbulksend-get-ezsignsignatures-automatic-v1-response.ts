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
import type { EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload } from './ezsignbulksend-get-ezsignsignatures-automatic-v1-response-mpayload';

/**
 * @type EzsignbulksendGetEzsignsignaturesAutomaticV1Response
 * Response for GET /1/object/ezsignbulksend/{pkiEzsignbulksendID}/getEzsignsignaturesAutomatic
 * @export
 */
/*export type EzsignbulksendGetEzsignsignaturesAutomaticV1Response = CommonResponse;*/
export interface EzsignbulksendGetEzsignsignaturesAutomaticV1Response {
    /**
     * 
     * @type {EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload}
     * @memberof EzsignbulksendGetEzsignsignaturesAutomaticV1Response
     */
    mPayload:EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendGetEzsignsignaturesAutomaticV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendGetEzsignsignaturesAutomaticV1Response
 */
export class DataObjectEzsignbulksendGetEzsignsignaturesAutomaticV1Response {
    mPayload:EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload = new DataObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendGetEzsignsignaturesAutomaticV1Response Validation Object
 * @class ValidationObjectEzsignbulksendGetEzsignsignaturesAutomaticV1Response
 */
export class ValidationObjectEzsignbulksendGetEzsignsignaturesAutomaticV1Response {
   mPayload = new ValidationObjectEzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload()
} 


