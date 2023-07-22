/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomFormsDataFolderResponse } from './custom-forms-data-folder-response';

/**
 * Payload for GET /1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getFormsData
 * @export
 * @interface EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload
 */
export interface EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload {
    /**
     * 
     * @type {Array<CustomFormsDataFolderResponse>}
     * @memberof EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload
     */
    'a_objFormsDataFolder': Array<CustomFormsDataFolderResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload
 */
export class DataObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload {
   a_objFormsDataFolder:Array<CustomFormsDataFolderResponse> = []
}

/**
 * @export 
 * A EzsignbulksendtransmissionGetFormsDataV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload
 */
export class ValidationObjectEzsignbulksendtransmissionGetFormsDataV1ResponseMPayload {
   a_objFormsDataFolder = {
      type: 'array',
      required: true
   }
} 


