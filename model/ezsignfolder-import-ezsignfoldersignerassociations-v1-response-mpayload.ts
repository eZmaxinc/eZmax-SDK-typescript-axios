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
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload
 */
export class DataObjectEzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload {
   a_pkiEzsignfoldersignerassociationID:Array<number> = []
}

/**
 * @export 
 * A EzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload
 */
export class ValidationObjectEzsignfolderImportEzsignfoldersignerassociationsV1ResponseMPayload {
   a_pkiEzsignfoldersignerassociationID = {
      type: 'array',
      required: true
   }
} 


