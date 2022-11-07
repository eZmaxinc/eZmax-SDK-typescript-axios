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


// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureAttachmentnamesource } from './field-eezsignsignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureFont } from './field-eezsignsignature-font';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureTooltipposition } from './field-eezsignsignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureType } from './field-eezsignsignature-type';

import { DefaultObject } from '../base'

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
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    'fkiEzsigndocumentID': number;
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
     * The Y coordinate (Vertical) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
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
     * A tooltip that will be presented to Ezsignsigner about the Ezsignsignature
     * @type {string}
     * @memberof EzsignsignatureResponse
     */
    'tEzsignsignatureTooltip'?: string;
    /**
     * 
     * @type {FieldEEzsignsignatureTooltipposition}
     * @memberof EzsignsignatureResponse
     */
    'eEzsignsignatureTooltipposition'?: FieldEEzsignsignatureTooltipposition;
    /**
     * 
     * @type {FieldEEzsignsignatureFont}
     * @memberof EzsignsignatureResponse
     */
    'eEzsignsignatureFont'?: FieldEEzsignsignatureFont;
    /**
     * The step when the Ezsignsigner will be invited to validate the Ezsignsignature of eEzsignsignatureType Attachments
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    'iEzsignsignatureValidationstep'?: number;
    /**
     * The description attached to the attachment name added in Ezsignsignature of eEzsignsignatureType Attachments
     * @type {string}
     * @memberof EzsignsignatureResponse
     */
    'sEzsignsignatureAttachmentdescription'?: string;
    /**
     * 
     * @type {FieldEEzsignsignatureAttachmentnamesource}
     * @memberof EzsignsignatureResponse
     */
    'eEzsignsignatureAttachmentnamesource'?: FieldEEzsignsignatureAttachmentnamesource;
    /**
     * Whether the Ezsignsignature is required or not. This field is relevant only with Ezsignsignature with eEzsignsignatureType = Attachments.
     * @type {boolean}
     * @memberof EzsignsignatureResponse
     */
    'bEzsignsignatureRequired'?: boolean;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureResponse
     */
    'fkiEzsignfoldersignerassociationIDValidation'?: number;
}
/**
 * A EzsignsignatureResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignsignatureResponse
 */
export class DefaultObjectEzsignsignatureResponse extends DefaultObject {
   pkiEzsignsignatureID:number = 0
   fkiEzsigndocumentID:number = 0
   fkiEzsignfoldersignerassociationID:number = 0
   iEzsignpagePagenumber:number = 0
   iEzsignsignatureX:number = 0
   iEzsignsignatureY:number = 0
   iEzsignsignatureStep:number = 0
   eEzsignsignatureType:FieldEEzsignsignatureType = 'Acknowledgement'
   tEzsignsignatureTooltip?:string = undefined
   eEzsignsignatureTooltipposition?:FieldEEzsignsignatureTooltipposition = undefined
   eEzsignsignatureFont?:FieldEEzsignsignatureFont = undefined
   iEzsignsignatureValidationstep?:number = undefined
   sEzsignsignatureAttachmentdescription?:string = undefined
   eEzsignsignatureAttachmentnamesource?:FieldEEzsignsignatureAttachmentnamesource = undefined
   bEzsignsignatureRequired?:boolean = undefined
   fkiEzsignfoldersignerassociationIDValidation?:number = undefined
}


