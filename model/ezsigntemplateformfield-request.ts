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
 * A Ezsigntemplateformfield Object
 * @export
 * @interface EzsigntemplateformfieldRequest
 */
export interface EzsigntemplateformfieldRequest {
    /**
     * The unique ID of the Ezsigntemplateformfield
     * @type {number}
     * @memberof EzsigntemplateformfieldRequest
     */
    'pkiEzsigntemplateformfieldID'?: number;
    /**
     * The page number in the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplateformfieldRequest
     */
    'iEzsigntemplatedocumentpagePagenumber': number;
    /**
     * The Label for the Ezsigntemplateformfield
     * @type {string}
     * @memberof EzsigntemplateformfieldRequest
     */
    'sEzsigntemplateformfieldLabel': string;
    /**
     * The value for the Ezsigntemplateformfield  This can only be set if eEzsigntemplateformfieldgroupType is Checkbox or Radio
     * @type {string}
     * @memberof EzsigntemplateformfieldRequest
     */
    'sEzsigntemplateformfieldValue'?: string;
    /**
     * The X coordinate (Horizontal) where to put the Ezsigntemplateformfield on the Ezsigntemplatepage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplateformfield 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsigntemplateformfieldRequest
     */
    'iEzsigntemplateformfieldX': number;
    /**
     * The Y coordinate (Vertical) where to put the Ezsigntemplateformfield on the Ezsigntemplatepage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplateformfield 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsigntemplateformfieldRequest
     */
    'iEzsigntemplateformfieldY': number;
    /**
     * The Width of the Ezsigntemplateformfield in pixels calculated at 100 DPI  The allowed values are varying based on the eEzsigntemplateformfieldgroupType.  | eEzsigntemplateformfieldgroupType | Valid values | | ------------------------- | ------------ | | Checkbox                  | 22           | | Dropdown                  | 22-65535     | | Radio                     | 22           | | Text                      | 22-65535     | | Textarea                  | 22-65535     |
     * @type {number}
     * @memberof EzsigntemplateformfieldRequest
     */
    'iEzsigntemplateformfieldWidth': number;
    /**
     * The Height of the Ezsigntemplateformfield in pixels calculated at 100 DPI  The allowed values are varying based on the eEzsigntemplateformfieldgroupType.  | eEzsigntemplateformfieldgroupType | Valid values | | ------------------------- | ------------ | | Checkbox                  | 22           | | Dropdown                  | 22           | | Radio                     | 22           | | Text                      | 22           | | Textarea                  | 22-65535     | 
     * @type {number}
     * @memberof EzsigntemplateformfieldRequest
     */
    'iEzsigntemplateformfieldHeight': number;
    /**
     * Whether the Ezsigntemplateformfield is selected or not by default.  This can only be set if eEzsigntemplateformfieldgroupType is **Checkbox** or **Radio**
     * @type {boolean}
     * @memberof EzsigntemplateformfieldRequest
     */
    'bEzsigntemplateformfieldSelected'?: boolean;
}

