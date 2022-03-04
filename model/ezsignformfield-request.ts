/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.6
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Ezsignformfield Object
 * @export
 * @interface EzsignformfieldRequest
 */
export interface EzsignformfieldRequest {
    /**
     * The unique ID of the Ezsignformfield
     * @type {number}
     * @memberof EzsignformfieldRequest
     */
    'pkiEzsignformfieldID'?: number;
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignformfieldRequest
     */
    'iEzsignpagePagenumber': number;
    /**
     * The Label for the Ezsignformfield
     * @type {string}
     * @memberof EzsignformfieldRequest
     */
    'sEzsignformfieldLabel': string;
    /**
     * The value for the Ezsignformfield  This can only be set if eEzsignformfieldgroupType is Checkbox or Radio
     * @type {string}
     * @memberof EzsignformfieldRequest
     */
    'sEzsignformfieldValue'?: string;
    /**
     * The X coordinate (Horizontal) where to put the Ezsignformfield on the Ezsignpage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignformfield 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignformfieldRequest
     */
    'iEzsignformfieldX': number;
    /**
     * The Y coordinate (Vertical) where to put the Ezsignformfield on the Ezsignpage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignformfield 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignformfieldRequest
     */
    'iEzsignformfieldY': number;
    /**
     * The Width of the Ezsignformfield in pixels calculated at 100 DPI  The allowed values are varying based on the eEzsignformfieldgroupType.  | eEzsignformfieldgroupType | Valid values | | ------------------------- | ------------ | | Checkbox                  | 22           | | Dropdown                  | 22-65535     | | Radio                     | 22           | | Text                      | 22-65535     | | Textarea                  | 22-65535     |
     * @type {number}
     * @memberof EzsignformfieldRequest
     */
    'iEzsignformfieldWidth': number;
    /**
     * The Height of the Ezsignformfield in pixels calculated at 100 DPI  The allowed values are varying based on the eEzsignformfieldgroupType.  | eEzsignformfieldgroupType | Valid values | | ------------------------- | ------------ | | Checkbox                  | 22           | | Dropdown                  | 22           | | Radio                     | 22           | | Text                      | 22           | | Textarea                  | 22-65535     | 
     * @type {number}
     * @memberof EzsignformfieldRequest
     */
    'iEzsignformfieldHeight': number;
    /**
     * Whether the Ezsignformfield is selected or not by default.  This can only be set if eEzsignformfieldgroupType is **Checkbox** or **Radio**
     * @type {boolean}
     * @memberof EzsignformfieldRequest
     */
    'bEzsignformfieldSelected'?: boolean;
    /**
     * This is the value enterred for the Ezsignformfield  This can only be set if eEzsignformfieldgroupType is **Dropdown**, **Text** or **Textarea**
     * @type {string}
     * @memberof EzsignformfieldRequest
     */
    'sEzsignformfieldEnteredvalue'?: string;
}
