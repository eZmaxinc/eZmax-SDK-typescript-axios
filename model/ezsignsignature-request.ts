/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.1
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
 * @interface EzsignsignatureRequest
 */
export interface EzsignsignatureRequest {
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'fkiEzsignfoldersignerassociationID': number;
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignpagePagenumber': number;
    /**
     * The X coordinate (Horizontal) where to put the signature block on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the signature block 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureX': number;
    /**
     * The Y coordinate (Vertical) where to put the signature block on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the signature block 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureY': number;
    /**
     * The step when the Ezsignsigner will be invited to sign.
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureStep': number;
    /**
     * 
     * @type {FieldEEzsignsignatureType}
     * @memberof EzsignsignatureRequest
     */
    'eEzsignsignatureType': FieldEEzsignsignatureType;
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'fkiEzsigndocumentID': number;
}

