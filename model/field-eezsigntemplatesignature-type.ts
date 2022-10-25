/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The type of signature.  1. **Acknowledgement** is for an acknowledgment of receipt. 2. **City** is to request the city where the document is signed. 3. **Handwritten** is for a handwritten kind of signature where users needs to \"draw\" their signature on screen. 4. **Initials** is a simple \"click to add initials\" block. 5. **Name** is a simple \"Click to sign\" block. This is the most common block of signature. 6. **Attachments** is to ask for files as attachment that may be validate in another step.    
 * @export
 * @enum {string}
 */

export const FieldEEzsigntemplatesignatureType = {
    Acknowledgement: 'Acknowledgement',
    City: 'City',
    Handwritten: 'Handwritten',
    Initials: 'Initials',
    Name: 'Name',
    Attachments: 'Attachments'
} as const;

export type FieldEEzsigntemplatesignatureType = typeof FieldEEzsigntemplatesignatureType[keyof typeof FieldEEzsigntemplatesignatureType];



