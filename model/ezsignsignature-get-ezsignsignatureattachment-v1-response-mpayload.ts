/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureattachmentResponse } from './ezsignsignatureattachment-response';

/**
 * Response for GET /1/object/ezsignsignature/{pkiEzsignsignatureID}/getEzsignsignatureattachment
 * @export
 * @interface EzsignsignatureGetEzsignsignatureattachmentV1ResponseMPayload
 */
export interface EzsignsignatureGetEzsignsignatureattachmentV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignsignatureattachmentResponse>}
     * @memberof EzsignsignatureGetEzsignsignatureattachmentV1ResponseMPayload
     */
    'a_objEzsignsignatureattachment': Array<EzsignsignatureattachmentResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignatureGetEzsignsignatureattachmentV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureGetEzsignsignatureattachmentV1ResponseMPayload
 */
export class DataObjectEzsignsignatureGetEzsignsignatureattachmentV1ResponseMPayload {
   a_objEzsignsignatureattachment:Array<EzsignsignatureattachmentResponse> = []
}

/**
 * @export 
 * A EzsignsignatureGetEzsignsignatureattachmentV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignsignatureGetEzsignsignatureattachmentV1ResponseMPayload
 */
export class ValidationObjectEzsignsignatureGetEzsignsignatureattachmentV1ResponseMPayload {
   a_objEzsignsignatureattachment = {
      type: 'array',
      required: true
   }
} 

