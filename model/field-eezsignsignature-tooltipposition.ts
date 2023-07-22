/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The location of the tooltip relative to the Ezsignsignature\'s location.
 * @export
 * @enum {string}
 */

export const FieldEEzsignsignatureTooltipposition = {
    TopLeft: 'TopLeft',
    TopCenter: 'TopCenter',
    TopRight: 'TopRight',
    MiddleLeft: 'MiddleLeft',
    MiddleRight: 'MiddleRight',
    BottomLeft: 'BottomLeft',
    BottomCenter: 'BottomCenter',
    BottomRight: 'BottomRight'
} as const;

export type FieldEEzsignsignatureTooltipposition = typeof FieldEEzsignsignatureTooltipposition[keyof typeof FieldEEzsignsignatureTooltipposition];



