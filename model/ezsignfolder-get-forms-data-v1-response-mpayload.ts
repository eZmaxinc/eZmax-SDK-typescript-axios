/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomFormsDataFolderResponse } from './custom-forms-data-folder-response';

import { DefaultObject } from '../base'

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
    'objFormsDataFolder': CustomFormsDataFolderResponse;
}
/**
 * A EzsignfolderGetFormsDataV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderGetFormsDataV1ResponseMPayload
 */
export class DefaultObjectEzsignfolderGetFormsDataV1ResponseMPayload extends DefaultObject {
   objFormsDataFolder:Partial<CustomFormsDataFolderResponse> = {}
}


