/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomFormDataDocumentResponse } from './custom-form-data-document-response';

import { DefaultObject } from '../base'

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
    'objFormDataDocument': CustomFormDataDocumentResponse;
}
/**
 * A EzsigndocumentGetFormDataV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentGetFormDataV1ResponseMPayload
 */
export class DefaultObjectEzsigndocumentGetFormDataV1ResponseMPayload extends DefaultObject {
   objFormDataDocument:Partial<CustomFormDataDocumentResponse> = {}
}


