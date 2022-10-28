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



import { DefaultObject } from '../base'

/**
 * Request for POST /2/object/ezsigndocument/{pkiEzsigndocumentID}/applyezsigntemplate
 * @export
 * @interface EzsigndocumentApplyEzsigntemplateV2Request
 */
export interface EzsigndocumentApplyEzsigntemplateV2Request {
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigndocumentApplyEzsigntemplateV2Request
     */
    'fkiEzsigntemplateID': number;
    /**
     * 
     * @type {Array<string>}
     * @memberof EzsigndocumentApplyEzsigntemplateV2Request
     */
    'a_sEzsigntemplatesigner': Array<string>;
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsigndocumentApplyEzsigntemplateV2Request
     */
    'a_pkiEzsignfoldersignerassociationID': Array<number>;
}
/**
 * A EzsigndocumentApplyEzsigntemplateV2Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentApplyEzsigntemplateV2Request
 */
export class DefaultObjectEzsigndocumentApplyEzsigntemplateV2Request extends DefaultObject {
   fkiEzsigntemplateID:number = 0
   a_sEzsigntemplatesigner:Array<string> = []
   a_pkiEzsignfoldersignerassociationID:Array<number> = []
}


