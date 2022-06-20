/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { FieldEEzsigntemplatesignatureFont } from './field-eezsigntemplatesignature-font';
import { FieldEEzsigntemplatesignatureTooltipposition } from './field-eezsigntemplatesignature-tooltipposition';
import { FieldEEzsigntemplatesignatureType } from './field-eezsigntemplatesignature-type';

/**
 * A Ezsigntemplatesignature Object
 * @export
 * @interface EzsigntemplatesignatureResponse
 */
export interface EzsigntemplatesignatureResponse {
    /**
     * The unique ID of the Ezsigntemplatesignature
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    'pkiEzsigntemplatesignatureID': number;
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    'fkiEzsigntemplatedocumentID': number;
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    'fkiEzsigntemplatesignerID': number;
    /**
     * The page number in the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    'iEzsigntemplatedocumentpagePagenumber': number;
    /**
     * The X coordinate (Horizontal) where to put the Ezsigntemplatesignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignature 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    'iEzsigntemplatesignatureX': number;
    /**
     * The Y coordinate (Vertical) where to put the Ezsigntemplatesignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignature 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    'iEzsigntemplatesignatureY': number;
    /**
     * The step when the Ezsigntemplatesigner will be invited to sign
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    'iEzsigntemplatesignatureStep': number;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureType}
     * @memberof EzsigntemplatesignatureResponse
     */
    'eEzsigntemplatesignatureType': FieldEEzsigntemplatesignatureType;
    /**
     * A tooltip that will be presented to Ezsigntemplatesigner about the Ezsigntemplatesignature
     * @type {string}
     * @memberof EzsigntemplatesignatureResponse
     */
    'tEzsigntemplatesignatureTooltip'?: string;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureTooltipposition}
     * @memberof EzsigntemplatesignatureResponse
     */
    'eEzsigntemplatesignatureTooltipposition'?: FieldEEzsigntemplatesignatureTooltipposition;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureFont}
     * @memberof EzsigntemplatesignatureResponse
     */
    'eEzsigntemplatesignatureFont'?: FieldEEzsigntemplatesignatureFont;
}

