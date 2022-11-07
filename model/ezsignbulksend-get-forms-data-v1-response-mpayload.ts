/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
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
 * Payload for GET/1/object/ezsignbulksend/{pkiEzsignbulksendID}/getFormsData
 * @export
 * @interface EzsignbulksendGetFormsDataV1ResponseMPayload
 */
export interface EzsignbulksendGetFormsDataV1ResponseMPayload {
    /**
     * 
     * @type {Array<CustomFormsDataFolderResponse>}
     * @memberof EzsignbulksendGetFormsDataV1ResponseMPayload
     */
    'a_objFormsDataFolder': Array<CustomFormsDataFolderResponse>;
}
/**
 * A EzsignbulksendGetFormsDataV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksendGetFormsDataV1ResponseMPayload
 */
export class DefaultObjectEzsignbulksendGetFormsDataV1ResponseMPayload extends DefaultObject {
   a_objFormsDataFolder:Array<CustomFormsDataFolderResponse> = []
}


