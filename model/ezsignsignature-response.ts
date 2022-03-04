/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { FieldEEzsignsignatureType } from './field-eezsignsignature-type';

/**
 * An Ezsignsignature Object
 * @export
 * @interface EzsignsignatureResponse
 */
export interface EzsignsignatureResponse {
    /**
     * The unique ID of the Ezsignsignature
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    'pkiEzsignsignatureID': number;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    'fkiEzsignfoldersignerassociationID': number;
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    'iEzsignpagePagenumber': number;
    /**
     * The X coordinate (Horizontal) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    'iEzsignsignatureX': number;
    /**
     * The Y coordinate (Vertical) where to put the signature block on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the signature block 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    'iEzsignsignatureY': number;
    /**
     * The step when the Ezsignsigner will be invited to sign
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    'iEzsignsignatureStep': number;
    /**
     * 
     * @type {FieldEEzsignsignatureType}
     * @memberof EzsignsignatureResponse
     */
    'eEzsignsignatureType': FieldEEzsignsignatureType;
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    'fkiEzsigndocumentID': number;
}

