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
import { CustomFormsDataFolderResponse } from './custom-forms-data-folder-response';

/**
 * Payload for GET /1/object/ezsignfolder/{pkiEzsigndocument}/getFormsData
 * @export
 * @interface EzsignfolderGetFormsDataV1ResponseMPayload
 */
export interface EzsignfolderGetFormsDataV1ResponseMPayload {
    /**
     * 
     * @type {CustomFormsDataFolderResponse}
     * @memberof EzsignfolderGetFormsDataV1ResponseMPayload
     */
    /*'objFormsDataFolder': CustomFormsDataFolderResponse;*/
    'objFormsDataFolder': CustomFormsDataFolderResponse;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomFormsDataFolderResponse } from './'
// @ts-ignore
import { ValidationObjectCustomFormsDataFolderResponse } from './'

/**
 * @export 
 * A EzsignfolderGetFormsDataV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetFormsDataV1ResponseMPayload
 */
export class DataObjectEzsignfolderGetFormsDataV1ResponseMPayload {
   objFormsDataFolder:CustomFormsDataFolderResponse = new DataObjectCustomFormsDataFolderResponse()
}

/**
 * @export 
 * A EzsignfolderGetFormsDataV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfolderGetFormsDataV1ResponseMPayload
 */
export class ValidationObjectEzsignfolderGetFormsDataV1ResponseMPayload {
   objFormsDataFolder = new ValidationObjectCustomFormsDataFolderResponse()
} 


