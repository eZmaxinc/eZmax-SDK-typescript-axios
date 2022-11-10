/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureAttachmentnamesource } from './field-eezsigntemplatesignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureFont } from './field-eezsigntemplatesignature-font';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureTooltipposition } from './field-eezsigntemplatesignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureType } from './field-eezsigntemplatesignature-type';

import { DefaultObject } from '../base'

/**
 * A Ezsigntemplatesignature Object
 * @export
 * @interface EzsigntemplatesignatureRequest
 */
export interface EzsigntemplatesignatureRequest {
    /**
     * The unique ID of the Ezsigntemplatesignature
     * @type {number}
     * @memberof EzsigntemplatesignatureRequest
     */
    'pkiEzsigntemplatesignatureID'?: number;
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatesignatureRequest
     */
    'fkiEzsigntemplatedocumentID': number;
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignatureRequest
     */
    'fkiEzsigntemplatesignerID': number;
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignatureRequest
     */
    'fkiEzsigntemplatesignerIDValidation'?: number;
    /**
     * The page number in the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatesignatureRequest
     */
    'iEzsigntemplatedocumentpagePagenumber': number;
    /**
     * The X coordinate (Horizontal) where to put the Ezsigntemplatesignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignature 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignatureRequest
     */
    'iEzsigntemplatesignatureX': number;
    /**
     * The Y coordinate (Vertical) where to put the Ezsigntemplatesignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignature 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignatureRequest
     */
    'iEzsigntemplatesignatureY': number;
    /**
     * The step when the Ezsigntemplatesigner will be invited to sign
     * @type {number}
     * @memberof EzsigntemplatesignatureRequest
     */
    'iEzsigntemplatesignatureStep': number;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureType}
     * @memberof EzsigntemplatesignatureRequest
     */
    'eEzsigntemplatesignatureType': FieldEEzsigntemplatesignatureType;
    /**
     * A tooltip that will be presented to Ezsigntemplatesigner about the Ezsigntemplatesignature
     * @type {string}
     * @memberof EzsigntemplatesignatureRequest
     */
    'tEzsigntemplatesignatureTooltip'?: string;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureTooltipposition}
     * @memberof EzsigntemplatesignatureRequest
     */
    'eEzsigntemplatesignatureTooltipposition'?: FieldEEzsigntemplatesignatureTooltipposition;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureFont}
     * @memberof EzsigntemplatesignatureRequest
     */
    'eEzsigntemplatesignatureFont'?: FieldEEzsigntemplatesignatureFont;
    /**
     * Whether the Ezsigntemplatesignature is required or not. This field is relevant only with Ezsigntemplatesignature with eEzsigntemplatesignatureType = Attachments.
     * @type {boolean}
     * @memberof EzsigntemplatesignatureRequest
     */
    'bEzsigntemplatesignatureRequired'?: boolean;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureAttachmentnamesource}
     * @memberof EzsigntemplatesignatureRequest
     */
    'eEzsigntemplatesignatureAttachmentnamesource'?: FieldEEzsigntemplatesignatureAttachmentnamesource;
    /**
     * The description attached to the attachment name added in Ezsigntemplatesignature of eEzsigntemplatesignatureType Attachments
     * @type {string}
     * @memberof EzsigntemplatesignatureRequest
     */
    'sEzsigntemplatesignatureAttachmentdescription'?: string;
    /**
     * The step when the Ezsigntemplatesigner will be invited to validate the Ezsigntemplatesignature of eEzsigntemplatesignatureType Attachments
     * @type {number}
     * @memberof EzsigntemplatesignatureRequest
     */
    'iEzsigntemplatesignatureValidationstep'?: number;
}
/**
 * A EzsigntemplatesignatureRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignatureRequest
 */
export class DefaultObjectEzsigntemplatesignatureRequest extends DefaultObject {
   pkiEzsigntemplatesignatureID?:number = undefined
   fkiEzsigntemplatedocumentID:number = 0
   fkiEzsigntemplatesignerID:number = 0
   fkiEzsigntemplatesignerIDValidation?:number = undefined
   iEzsigntemplatedocumentpagePagenumber:number = 0
   iEzsigntemplatesignatureX:number = 0
   iEzsigntemplatesignatureY:number = 0
   iEzsigntemplatesignatureStep:number = 0
   eEzsigntemplatesignatureType:FieldEEzsigntemplatesignatureType = 'Acknowledgement'
   tEzsigntemplatesignatureTooltip?:string = undefined
   eEzsigntemplatesignatureTooltipposition?:FieldEEzsigntemplatesignatureTooltipposition = undefined
   eEzsigntemplatesignatureFont?:FieldEEzsigntemplatesignatureFont = undefined
   bEzsigntemplatesignatureRequired?:boolean = undefined
   eEzsigntemplatesignatureAttachmentnamesource?:FieldEEzsigntemplatesignatureAttachmentnamesource = undefined
   sEzsigntemplatesignatureAttachmentdescription?:string = undefined
   iEzsigntemplatesignatureValidationstep?:number = undefined
}


