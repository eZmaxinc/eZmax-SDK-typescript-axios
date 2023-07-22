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
 * Request for POST /1/object/ezsignfolder/{pkiEzsignfolderID}/importEzsignfoldersignerassociations
 * @export
 * @interface EzsignfolderImportEzsignfoldersignerassociationsV1Request
 */
export interface EzsignfolderImportEzsignfoldersignerassociationsV1Request {
    /**
     * 
     * @type {Set<number>}
     * @memberof EzsignfolderImportEzsignfoldersignerassociationsV1Request
     */
    'a_fkiEzsignfoldersignerassociationID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderImportEzsignfoldersignerassociationsV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderImportEzsignfoldersignerassociationsV1Request
 */
export class DataObjectEzsignfolderImportEzsignfoldersignerassociationsV1Request {
   a_fkiEzsignfoldersignerassociationID:Array<number> = []
}

/**
 * @export 
 * A EzsignfolderImportEzsignfoldersignerassociationsV1Request Validation Object
 * @class ValidationObjectEzsignfolderImportEzsignfoldersignerassociationsV1Request
 */
export class ValidationObjectEzsignfolderImportEzsignfoldersignerassociationsV1Request {
   a_fkiEzsignfoldersignerassociationID = {
      type: 'array',
      unique: true,
      minItems: 1,
      required: true
   }
} 


