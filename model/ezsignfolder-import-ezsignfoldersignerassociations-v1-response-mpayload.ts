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



import { DefaultObject } from '../base'

/**
 * Payload for POST /1/object/ezsignfolder/{pkiEzsignfolder}/importEzsignfoldersignerassociations
 * @export
 * @interface EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload
 */
export interface EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload
     */
    'a_pkiEzsignfoldersignerassociationID': Array<number>;
}
/**
 * A EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload
 */
export class DefaultObjectEzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload extends DefaultObject {
   a_pkiEzsignfoldersignerassociationID:Array<number> = []
}


