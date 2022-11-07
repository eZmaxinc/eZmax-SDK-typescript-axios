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
/**
 * A CustomImportEzsigntemplatepackageRelationRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomImportEzsigntemplatepackageRelationRequest
 */
export class DefaultObjectCustomImportEzsigntemplatepackageRelationRequest extends DefaultObject {
   fkiEzsigntemplatepackagesignerID?:number = undefined
   fkiEzsignfoldersignerassociationID:number = 0
   sEzsigntemplatepackagesignerDescription?:string = undefined
}


