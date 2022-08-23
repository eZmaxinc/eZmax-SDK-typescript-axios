/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



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

