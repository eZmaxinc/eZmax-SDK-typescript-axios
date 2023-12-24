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
import { CustomAttachmentdocumenttypeResponse } from './custom-attachmentdocumenttype-response';

/**
 * Response for GET /1/object/inscription/{pkiInscriptionID}/getAttachments
 * @export
 * @interface InscriptionGetAttachmentsV1ResponseMPayload
 */
export interface InscriptionGetAttachmentsV1ResponseMPayload {
    /**
     * 
     * @type {Array<CustomAttachmentdocumenttypeResponse>}
     * @memberof InscriptionGetAttachmentsV1ResponseMPayload
     */
    'a_objAttachmentdocumenttype': Array<CustomAttachmentdocumenttypeResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A InscriptionGetAttachmentsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectInscriptionGetAttachmentsV1ResponseMPayload
 */
export class DataObjectInscriptionGetAttachmentsV1ResponseMPayload {
   a_objAttachmentdocumenttype:Array<CustomAttachmentdocumenttypeResponse> = []
}

/**
 * @export 
 * A InscriptionGetAttachmentsV1ResponseMPayload Validation Object
 * @class ValidationObjectInscriptionGetAttachmentsV1ResponseMPayload
 */
export class ValidationObjectInscriptionGetAttachmentsV1ResponseMPayload {
   a_objAttachmentdocumenttype = {
      type: 'array',
      required: true
   }
} 

