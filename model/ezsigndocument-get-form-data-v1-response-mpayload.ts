/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CustomFormDataDocumentResponse } from './custom-form-data-document-response';

/**
 * Payload for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getFormData
 * @export
 * @interface EzsigndocumentGetFormDataV1ResponseMPayload
 */
export interface EzsigndocumentGetFormDataV1ResponseMPayload {
    /**
     * 
     * @type {CustomFormDataDocumentResponse}
     * @memberof EzsigndocumentGetFormDataV1ResponseMPayload
     */
    /*'objFormDataDocument': CustomFormDataDocumentResponse;*/
    'objFormDataDocument': CustomFormDataDocumentResponse;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomFormDataDocumentResponse } from './'
// @ts-ignore
import { ValidationObjectCustomFormDataDocumentResponse } from './'

/**
 * @export 
 * A EzsigndocumentGetFormDataV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetFormDataV1ResponseMPayload
 */
export class DataObjectEzsigndocumentGetFormDataV1ResponseMPayload {
   objFormDataDocument:CustomFormDataDocumentResponse = new DataObjectCustomFormDataDocumentResponse()
}

/**
 * @export 
 * A EzsigndocumentGetFormDataV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndocumentGetFormDataV1ResponseMPayload
 */
export class ValidationObjectEzsigndocumentGetFormDataV1ResponseMPayload {
   objFormDataDocument = new ValidationObjectCustomFormDataDocumentResponse()
} 


