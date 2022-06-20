/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * An Ezsignfoldersignerassociation Object
 * @export
 * @interface EzsignfoldersignerassociationResponse
 */
export interface EzsignfoldersignerassociationResponse {
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignfoldersignerassociationResponse
     */
    'pkiEzsignfoldersignerassociationID': number;
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfoldersignerassociationResponse
     */
    'fkiEzsignfolderID': number;
    /**
     * If this flag is true. The signatory will receive a copy of every signed Ezsigndocument even if it ain\'t required to sign the document.
     * @type {boolean}
     * @memberof EzsignfoldersignerassociationResponse
     */
    'bEzsignfoldersignerassociationReceivecopy': boolean;
}

