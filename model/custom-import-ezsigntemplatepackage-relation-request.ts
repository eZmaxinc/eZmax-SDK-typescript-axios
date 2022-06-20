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
 * The object used in /1/object/ezsignfolder/{pkiEzsignfolderID}/importEzsigntemplatepackage Request
 * @export
 * @interface CustomImportEzsigntemplatepackageRelationRequest
 */
export interface CustomImportEzsigntemplatepackageRelationRequest {
    /**
     * The unique ID of the Ezsigntemplatepackagesigner
     * @type {number}
     * @memberof CustomImportEzsigntemplatepackageRelationRequest
     */
    'fkiEzsigntemplatepackagesignerID'?: number;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof CustomImportEzsigntemplatepackageRelationRequest
     */
    'fkiEzsignfoldersignerassociationID': number;
    /**
     * The description of the Ezsigntemplatepackagesigner
     * @type {string}
     * @memberof CustomImportEzsigntemplatepackageRelationRequest
     */
    'sEzsigntemplatepackagesignerDescription'?: string;
}

