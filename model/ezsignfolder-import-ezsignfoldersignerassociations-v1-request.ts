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



import { DefaultObject } from '../base'

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
    'a_fkiEzsignfoldersignerassociationID': Set<number>;
}
/**
 * A EzsignfolderImportEzsignfoldersignerassociationsV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderImportEzsignfoldersignerassociationsV1Request
 */
export class DefaultObjectEzsignfolderImportEzsignfoldersignerassociationsV1Request extends DefaultObject {
   a_fkiEzsignfoldersignerassociationID:Set<number> = new Set()
}

